# Level 1: n8n workflow

`vulntriage_workflow.json` is exported from the running n8n instance
(Community Edition 2.48.7, self-hosted with Docker). It contains no secrets:
every key is read at runtime with `$env` and the Postgres credential is only
referenced by name.

## Nodes

| # | Node | Type | Role |
|---|------|------|------|
| 1 | Receive scan report | Webhook (POST `/webhook/vulntriage`) | Trigger. Body: `{report, asset, inventory?, run_id?, notify?, pdf?}` with an Nmap XML or Nuclei JSONL report and the host inventory (lab) entries. |
| 2 | Parse scan report | Code | Extracts host, port, service, product, version, CPE and CVE ids; joins the host inventory (real lab IP and PID). |
| 3 | Has CVE ids? | IF | Findings with CVE ids go straight on; the rest go to the CPE lookup. |
| 4 | NVD CPE lookup | HTTP Request | NVD API 2.0 `virtualMatchString` with the service CPE (throttled: 1 request per 700 ms). |
| 5 | Top CVEs from CPE | Code | Keeps the 3 highest-CVSS CVEs for the detected version. |
| 6 | Join CVE sources | Merge | Joins both branches. |
| 7 | One item per CVE | Code | One item per (host, port, CVE), deduplicated, capped at 12. |
| 8 | CVEs linked? | IF | Reports without any linkable CVE end in node 9. |
| 9 | Respond no findings | Respond to Webhook | Returns `findings: 0`. |
| 10 | NVD CVE details | HTTP Request | CVSS, vector, CWE and description per CVE. |
| 11 | FIRST EPSS | HTTP Request | Probability of exploitation in the next 30 days. |
| 12 | CISA KEV catalog | HTTP Request (execute once) | Known Exploited Vulnerabilities catalog. |
| 13 | Combine intel | Code | Joins NVD, EPSS and KEV; flags critical = in KEV or CVSS >= 9. |
| 14 | Build LLM prompt | Code | One prompt per report (keeps the free-tier quota). |
| 15 | Gemini summarize | HTTP Request | Gemini Flash-Lite (temperature 0.1 requested; this model applies fixed sampling defaults), JSON output: summary and ATT&CK technique per finding. |
| 16 | Groq fallback | HTTP Request | Runs only from the Gemini error output (quota, 429, 5xx). |
| 17 | Parse LLM output | Code | Accepts Gemini or Groq output; degrades to intel-only if both fail. |
| 18 | Log findings to Postgres | Postgres | Inserts every enriched finding into `vulntriage.findings`. |
| 19 | Aggregate run | Code | Run summary and the five-field alert text (host IP, PID, service, CVE info, recommendation). |
| 20 | Critical findings? (KEV or CVSS >= 9) | IF | Routes runs with critical findings to Telegram. |
| 21 | Telegram alert | HTTP Request | Telegram Bot API `sendMessage`. |
| 22 | Respond with triage | Respond to Webhook | Returns the triage JSON to the caller. |
| 23 | PDF report requested? | IF | Optional branch, after the response, when the request has `"pdf": true`. |
| 24 | Generate PDF report (LangChain) | HTTP Request | Calls the local bridge `langchain_agent/api.py`, which runs the LangChain agent (fuzzy priority) and sends the PDF report to Telegram. |

## Deploy and test

```bash
docker compose up -d                      # n8n + Postgres (reads .env)
./workflow/deploy.sh                      # generate, import, activate, export
curl -s -X POST http://localhost:5678/webhook/vulntriage \
  -H 'Content-Type: application/json' \
  --data "$(jq -n --rawfile r data/lab_scans/nmap_host12.xml '{report:$r, asset:"lab-httpd"}')"
```

The workflow is authored in `build_workflow.py` (reviewable code), imported
with the n8n CLI and exported back from the live instance. The Postgres
credential is created once with `n8n import:credentials` (see the main README).

## Optional PDF report from n8n

```bash
uv run python -m langchain_agent.api        # bridge on http://172.17.0.1:8765 (Docker gateway only)
# then send "pdf": true in the webhook body; n8n answers first, then triggers the PDF
```

## Metrics

`uv run python workflow/measure_executions.py --runs 24` sends the lab
reports to the webhook and reads the execution records n8n stored in Postgres.
Results: `metrics/n8n_metrics.json` and `metrics/executions.csv`.
