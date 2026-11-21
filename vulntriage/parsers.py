"""Parsers for Nmap XML (-sV -oX) and Nuclei JSONL (-jsonl) scan reports.

Both return a flat list of findings with the same shape:
{host, port, protocol, service, product, version, cpe, cves, source, title, severity}
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Nmap sometimes reports a product and version without a matching CPE (or with the
# interpreter CPE only, as for Werkzeug). These NVD vendor:product pairs close the gap.
PRODUCT_CPE = {
    "Werkzeug httpd": "palletsprojects:werkzeug",
    "Apache Tomcat": "apache:tomcat",
    "Apache Solr": "apache:solr",
    "Apache httpd": "apache:http_server",
    "Jetty": "eclipse:jetty",
    "Elasticsearch REST API": "elastic:elasticsearch",
}


def service_cpe23(product: str | None, version: str | None, cpes: list[str]) -> str | None:
    """Best CPE 2.3 match string for a service: product table first, then Nmap's CPEs.

    Versions with wildcards or ranges (2.4.x, 3.X - 4.X, snapshots) are skipped because
    they would match far too many CVEs.
    """
    def concrete(v: str | None) -> bool:
        return bool(v) and re.fullmatch(r"[0-9][0-9A-Za-z._-]*", v) is not None \
            and "x" not in v.lower().split(".") and "snapshot" not in v.lower()

    if product in PRODUCT_CPE and concrete(version):
        return f"cpe:2.3:a:{PRODUCT_CPE[product]}:{version}:*:*:*:*:*:*:*"
    for cpe in cpes:
        parts = cpe[5:].split(":") if cpe.startswith("cpe:/") else []
        if len(parts) >= 4 and parts[0] == "a" and concrete(parts[3]):
            return "cpe:2.3:" + ":".join((parts + ["*"] * 11)[:11])
    return None


def parse_nmap_xml(xml_text: str) -> list[dict]:
    """Extract one finding per open port with service, version and CPE."""
    root = ET.fromstring(xml_text)
    findings = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else "unknown"
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            svc_attr = svc.attrib if svc is not None else {}
            cpes = [c.text for c in svc.findall("cpe")] if svc is not None else []
            script_text = " ".join(s.get("output", "") for s in port.findall("script"))
            findings.append({
                "host": address,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc_attr.get("name"),
                "product": svc_attr.get("product"),
                "version": svc_attr.get("version"),
                "cpe": cpes,
                "cpe23": service_cpe23(svc_attr.get("product"), svc_attr.get("version"), cpes),
                "cves": sorted({c.upper() for c in CVE_PATTERN.findall(script_text)}),
                "source": "nmap",
                "title": " ".join(x for x in (svc_attr.get("product"), svc_attr.get("version"))
                                  if x) or svc_attr.get("name"),
                "severity": None,
            })
    return findings


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Extract one finding per Nuclei match, keeping CVE ids from the template metadata."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        info = item.get("info", {})
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        template = item.get("template-id", "")
        cves = set(c.upper() for c in cves) | set(c.upper() for c in CVE_PATTERN.findall(template))
        host = item.get("host") or item.get("ip") or "unknown"
        port = item.get("port")
        findings.append({
            "host": item.get("ip") or host,
            "hostname": None,
            "port": int(port) if port not in (None, "") else None,
            "protocol": "tcp",
            "service": item.get("type"),
            "product": None,
            "version": None,
            "cpe": [],
            "cpe23": None,
            "cves": sorted(cves),
            "source": "nuclei",
            "title": info.get("name") or template,
            "severity": info.get("severity"),
            "template_id": template,
            "matched_at": item.get("matched-at"),
        })
    return findings


def parse_report(text: str) -> list[dict]:
    """Detect the report format (Nmap XML or Nuclei JSONL) and parse it."""
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return parse_nmap_xml(text)
    return parse_nuclei_jsonl(text)
