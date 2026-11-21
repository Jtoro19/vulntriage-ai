#!/usr/bin/env bash
# Regenerate the workflow, import it into the running n8n container, activate it
# and export the live version back to workflow/vulntriage_workflow.json.
set -euo pipefail
cd "$(dirname "$0")/.."
C=vulntriage-n8n-1
TMP=$(mktemp)
uv run python workflow/build_workflow.py > "$TMP"
docker cp "$TMP" "$C:/tmp/wf.json"
docker exec "$C" n8n import:workflow --input=/tmp/wf.json
docker exec "$C" n8n update:workflow --id=VulnTriageAI0001 --active=true
docker exec "$C" n8n export:workflow --id=VulnTriageAI0001 --pretty --output=/tmp/export.json
docker cp "$C:/tmp/export.json" "$TMP"
jq 'if type=="array" then .[0] else . end' "$TMP" > workflow/vulntriage_workflow.json
rm -f "$TMP"
echo "Deployed and exported workflow/vulntriage_workflow.json"
