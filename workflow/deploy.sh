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
docker exec "$C" n8n publish:workflow --id=VulnTriageAI0001
docker restart "$C" > /dev/null   # the running instance reloads published webhooks on start
until curl -s -o /dev/null -w "%{http_code}" http://localhost:5678/healthz | grep -q 200; do sleep 2; done
sleep 5
docker exec "$C" n8n export:workflow --id=VulnTriageAI0001 --pretty --output=/tmp/export.json
docker cp "$C:/tmp/export.json" "$TMP"
# Drop the sharing block: it holds the n8n owner account name and email.
jq 'if type=="array" then .[0] else . end | del(.shared)' "$TMP" > workflow/vulntriage_workflow.json
rm -f "$TMP"
echo "Deployed and exported workflow/vulntriage_workflow.json"
