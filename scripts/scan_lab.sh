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
  nmap -sV -Pn -p 1-10000 -oX "$RAW/$name.xml" "$ip" > /dev/null
  uv run python scripts/anonymize_scan.py "$RAW/$name.xml" "$OUT/$name.xml"
done

# Nuclei CVE templates are fetched once with a sparse git checkout (no internet in the lab).
if [[ ! -d .cache/nuclei-templates/http/cves ]]; then
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/projectdiscovery/nuclei-templates.git .cache/nuclei-templates
  git -C .cache/nuclei-templates sparse-checkout set http/cves network/cves
fi

# 2. Nuclei CVE templates over the services found by Nmap. Templates that confirm a
#    vulnerability by exploiting it (RCE, file read, injection, out-of-band callbacks)
#    are excluded, so Nuclei only fingerprints; raw requests and responses are not stored.
TARGETS="$RAW/targets.txt"
for ip in "${IPS[@]}"; do
  host=$(echo "$ip" | cut -d. -f4)
  { rg -o 'portid="(\d+)"><state state="open"' -r '$1' "$RAW/nmap_host$host.xml" || true; } \
    | while read -r port; do echo "http://$ip:$port"; done
done | sort -u > "$TARGETS"
docker run --rm --network vulntriage-lab_lab \
  -v "$PWD/.cache/nuclei-templates:/templates:ro" \
  -v "$RAW:/scan" projectdiscovery/nuclei:latest \
  -l /scan/targets.txt -t /templates/http/cves -t /templates/network/cves -severity critical,high,medium \
  -etags dos,intrusive,fuzz,rce,lfi,traversal,sqli,xss,ssrf,xxe,deserialization,oast,injection,file-upload \
  -omit-raw -disable-update-check -silent -jsonl -o /scan/nuclei.jsonl -rate-limit 50 || true
[[ -f "$RAW/nuclei.jsonl" ]] || : > "$RAW/nuclei.jsonl"
jq -c 'del(.request, .response, ."curl-command")' "$RAW/nuclei.jsonl" > "$RAW/nuclei_clean.jsonl"
uv run python scripts/anonymize_scan.py "$RAW/nuclei_clean.jsonl" "$OUT/nuclei_lab.jsonl"
# 3. Host inventory (lab): container, process and PID behind every listening port.
uv run python -m vulntriage.inventory > /dev/null
echo "Reports written to $OUT and data/inventory/lab_inventory.json"
