#!/usr/bin/env bash
# Scan ONLY the local lab containers (172.30.0.0/24, internal Docker network).
# Produces anonymized Nmap XML and Nuclei JSONL reports in data/lab_scans/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=data/lab_scans
RAW=$(mktemp -d)
trap 'rm -rf "$RAW"' EXIT
mkdir -p "$OUT"

# Targets are read from the running lab containers, never from user input.
mapfile -t IPS < <(docker network inspect vulntriage-lab_lab \
  --format '{{range .Containers}}{{.IPv4Address}}{{"\n"}}{{end}}' | cut -d/ -f1 | rg '^172\.30\.0\.' | sort -t. -k4 -n)
[[ ${#IPS[@]} -gt 0 ]] || { echo "Lab is not running" >&2; exit 1; }
for ip in "${IPS[@]}"; do
  [[ $ip =~ ^172\.30\.0\.[0-9]+$ ]] || { echo "Refusing non-lab target $ip" >&2; exit 1; }
done
echo "Scanning ${#IPS[@]} lab hosts: ${IPS[*]}"

# 1. Nmap service and version detection, one report per host.
for ip in "${IPS[@]}"; do
  name="nmap_host$(echo "$ip" | cut -d. -f4)"
  nmap -sV -Pn --version-light -p 1-10000 -oX "$RAW/$name.xml" "$ip" > /dev/null
  uv run python scripts/anonymize_scan.py "$RAW/$name.xml" "$OUT/$name.xml"
done

# 2. Nuclei CVE templates over the HTTP services found by Nmap.
TARGETS="$RAW/targets.txt"
for ip in "${IPS[@]}"; do
  host=$(echo "$ip" | cut -d. -f4)
  { rg -o 'portid="(\d+)"><state state="open"' -r '$1' "$RAW/nmap_host$host.xml" || true; } \
    | while read -r port; do echo "http://$ip:$port"; done
done | sort -u > "$TARGETS"
docker run --rm --network vulntriage-lab_lab \
  -v vulntriage_nuclei_templates:/root/nuclei-templates \
  -v vulntriage_nuclei_config:/root/.config/nuclei \
  -v "$RAW:/scan" projectdiscovery/nuclei:latest \
  -l /scan/targets.txt -tags cve -severity critical,high,medium \
  -disable-update-check -silent -jsonl -o /scan/nuclei.jsonl -rate-limit 50 || true
touch "$RAW/nuclei.jsonl"
uv run python scripts/anonymize_scan.py "$RAW/nuclei.jsonl" "$OUT/nuclei_lab.jsonl"
echo "Reports written to $OUT:"; ls -1 "$OUT"
