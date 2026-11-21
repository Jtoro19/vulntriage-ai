"""Host inventory (lab): map each lab IP and port to its container and process PID.

A network scan cannot see process ids. This step runs on the machine that hosts
the lab containers and uses the Docker API (docker network inspect, docker
inspect, docker top, docker exec) to find, for every listening TCP port, the
process that owns the socket and its PID on the host. In a real engagement the
same information requires host access: an authenticated scan or an endpoint agent.

Usage: uv run python -m vulntriage.inventory   # writes data/inventory/lab_inventory.json
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from vulntriage.config import DATA_DIR

LAB_NETWORK = "vulntriage-lab_lab"
INVENTORY_PATH = DATA_DIR / "inventory" / "lab_inventory.json"
SOURCE_LABEL = "host inventory (lab)"

# Runs inside the container (when it has a shell): socket inode owners.
_PROBE = (
    "for p in /proc/[0-9]*; do for f in $p/fd/*; do l=$(readlink $f 2>/dev/null); "
    "case $l in socket:*) echo \"${p#/proc/} $l\";; esac; done; done"
)


def _run(cmd: list[str], timeout: int = 30) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout


def parse_listening(proc_net_tcp: str) -> dict[int, str]:
    """Return {port: socket inode} for non-loopback sockets in LISTEN state (st == 0A)."""
    ports: dict[int, str] = {}
    for line in proc_net_tcp.splitlines():
        parts = line.split()
        if len(parts) < 10 or parts[3] != "0A" or ":" not in parts[1]:
            continue
        addr, port_hex = parts[1].rsplit(":", 1)
        if addr.endswith("7F") or addr == "00000000000000000000000001000000":
            continue  # loopback (for example Docker's embedded DNS on 127.0.0.11)
        port = int(port_hex, 16)
        ports.setdefault(port, parts[9])
    return ports


def parse_socket_owners(text: str) -> dict[str, int]:
    """Return {socket inode: lowest container pid owning it}."""
    owners: dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"^(\d+) socket:\[(\d+)\]$", line.strip())
        if m:
            pid, inode = int(m.group(1)), m.group(2)
            owners[inode] = min(pid, owners.get(inode, pid))
    return owners


def _host_pid_map(container: str) -> dict[int, dict]:
    """Map container pid -> {host_pid, user, command} using docker top and /proc NSpid."""
    out = _run(["docker", "top", container, "-eo", "pid,user,args"])
    result: dict[int, dict] = {}
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        host_pid, user, args = int(parts[0]), parts[1], parts[2]
        try:
            status = Path(f"/proc/{host_pid}/status").read_text()
            nspid = re.search(r"^NSpid:\s+(.+)$", status, re.M).group(1).split()
            cpid = int(nspid[-1])
        except (OSError, AttributeError, ValueError):
            continue
        result[cpid] = {"host_pid": host_pid, "user": user, "command": args[:200]}
    return result


def lab_containers(network: str = LAB_NETWORK) -> list[dict]:
    """Containers attached to the lab network with their IPv4 address."""
    raw = _run(["docker", "network", "inspect", network])
    if not raw.strip():
        return []
    data = json.loads(raw)[0]
    items = []
    for cid, c in (data.get("Containers") or {}).items():
        ip = c["IPv4Address"].split("/")[0]
        if not ip.startswith("172.30.0."):
            continue  # only the isolated lab subnet
        image = _run(["docker", "inspect", "-f", "{{.Config.Image}}", cid]).strip()
        items.append({"id": cid[:12], "name": c["Name"], "ip": ip, "image": image})
    return sorted(items, key=lambda x: int(x["ip"].rsplit(".", 1)[1]))


def build_inventory(network: str = LAB_NETWORK) -> dict:
    """Build {"lab-host-N:port": entry} for every listening port of every lab container."""
    entries: dict[str, dict] = {}
    for c in lab_containers(network):
        main_pid = _run(["docker", "inspect", "-f", "{{.State.Pid}}", c["name"]]).strip()
        net = ""
        for name in ("tcp", "tcp6"):  # the container network namespace, read from the host
            try:
                net += Path(f"/proc/{main_pid}/net/{name}").read_text()
            except OSError:
                pass
        listening = parse_listening(net)
        owners = parse_socket_owners(
            _run(["docker", "exec", c["name"], "sh", "-c", _PROBE], timeout=60))
        pids = _host_pid_map(c["name"])
        if not owners and len(pids) == 1:  # no shell in the image, single process
            only = next(iter(pids))
            owners = dict.fromkeys(listening.values(), only)
        octet = c["ip"].rsplit(".", 1)[1]
        for port, inode in sorted(listening.items()):
            cpid = owners.get(inode)
            proc = pids.get(cpid, {}) if cpid else {}
            entries[f"lab-host-{octet}:{port}"] = {
                "ip": c["ip"], "port": port, "container": c["name"], "image": c["image"],
                "pid": proc.get("host_pid") or (int(main_pid) if main_pid.isdigit() else None),
                "pid_in_container": cpid,
                "pid_method": "socket owner" if proc else "container main process",
                "user": proc.get("user"), "command": proc.get("command"),
                "source": SOURCE_LABEL,
            }
    return {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "source": SOURCE_LABEL, "network": network, "entries": entries}


def load_inventory(path: Path = INVENTORY_PATH) -> dict:
    """Load the saved inventory entries (empty dict if the file does not exist)."""
    return json.loads(path.read_text())["entries"] if path.exists() else {}


def lookup(inventory: dict, host: str | None, port: int | None) -> dict | None:
    """Find the inventory entry for an anonymized host (lab-host-N) or a lab IP and port."""
    if not host or port is None:
        return None
    m = re.search(r"(?:lab-host-|172\.30\.0\.)(\d+)$", str(host))
    return inventory.get(f"lab-host-{m.group(1)}:{int(port)}") if m else None


if __name__ == "__main__":
    inv = build_inventory()
    INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY_PATH.write_text(json.dumps(inv, indent=2) + "\n")
    for key, e in inv["entries"].items():
        print(f"{key:22s} {e['ip']}:{e['port']:<5} pid={e['pid']} ({e['pid_method']}) "
              f"{(e['command'] or '')[:60]}")
    print(f"wrote {INVENTORY_PATH}")
