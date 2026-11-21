# Level 2: LangChain ReAct agent with RAG

A LangGraph ReAct agent triages an Nmap/Nuclei scan: it calls verifiable tools (NVD, EPSS, CISA KEV,
ATT&CK, a RAG knowledge base, the fuzzy prioritizer), then a final structured step produces a
Pydantic-validated report. Numeric fields (CVSS, EPSS, KEV, priority, fired rules) are overwritten
with the values the tools actually returned, so the model cannot invent them.

## Components

| Component | Choice | Justification |
|---|---|---|
| LLM (`llm.py`) | Provider switch `VULNTRIAGE_LLM_PROVIDER` = gemini, groq or ollama; temperature 0.1; model ids from `vulntriage/config.py` | Low temperature gives consistent output. Gemini and Groq fall back to each other on 429 or server errors; Ollama is local and has no cloud fallback by default (engagement data stays on the machine). Tools are bound on every model before `.with_fallbacks()` because the fallback wrapper has no `bind_tools`. |
| ChatPromptTemplate (`prompts.py`) | System: pentest analyst on authorized assets, never exploits, one-sentence reason before every tool call, cite sources and fuzzy rules. Human: `{asset_context}`, `{findings}` | Separates role, data and output rules. |
| Tools (`tools.py`) | `parse_scan`, `query_nvd`, `query_epss`, `is_in_kev`, `search_attack`, `search_knowledge`, `prioritize_risk` | NVD/EPSS/KEV give verifiable scores (cached clients from `vulntriage.intel`). `search_attack` maps weaknesses to ATT&CK. `search_knowledge` is RAG (top-k 4, with source, title, url). `prioritize_risk` wraps `fuzzy.fuzzy_engine.prioritize` and returns the fired rules for auditability. Outputs are compact JSON with truncated descriptions to save tokens. |
| Agent (`agent.py`) | LangGraph `create_react_agent` (dynamic model callable so the fallback chain keeps its tools) | The Thought, Action, Observation trace is auditable and saved per run. |
| Output (`schemas.py`) | Pydantic `Finding` and `Report`, via `with_structured_output` in a final formatting step, then validated and grounded | Structured, validated output before writing to disk. |

## RAG index

`uv run python -m langchain_agent.rag_index` (add `--rebuild` to redo it). Raw downloads are cached in
`data/cache/rag/`; the FAISS index goes to `langchain_agent/index/` (gitignored).

- Sources: OWASP WSTG (171 markdown docs, testing categories), MITRE CWE catalog (956 non-deprecated
  weaknesses: id, name, description, mitigations), MITRE ATT&CK (706 techniques).
- Chunking: `RecursiveCharacterTextSplitter`, 1200 chars, 150 overlap, giving 4582 chunks; the document
  title is prefixed to every chunk. Metadata: source, title, url.
- Embeddings: local fastembed `BAAI/bge-small-en-v1.5` (384 dims, CPU). The Gemini API does list
  `gemini-embedding-001` and `gemini-embedding-2`, but the free tier has a low requests-per-minute and
  daily quota and the corpus has thousands of chunks, so local embeddings are faster, need no key or
  quota and make the index reproducible. Index build took about 135 s on this machine.
- Known limitation: bge-small is a small model; queries that use the CWE id and name returned by NVD
  (the prompt asks for this) retrieve better than free text.

## Run

```bash
uv run python -m langchain_agent.rag_index
uv run python -m langchain_agent.run --scan data/lab_scans/nmap_host12.xml \
    --asset "lab web server" --exposure 8 --criticality 7
# other providers
VULNTRIAGE_LLM_PROVIDER=ollama uv run python -m langchain_agent.run --scan ... --asset ...
```

Outputs: `reports/<run_id>.md|json` and `langchain_agent/traces/<run_id>.md|json`. `--db DSN` inserts the
findings into Postgres (`pipeline='langchain'`) but needs `psycopg`, which is not a project dependency, and
was not exercised. Tests: `uv run pytest tests/test_agent.py -q` (offline).

## Multi-host runs, alerts, PDF and host inventory

```bash
uv run python -m langchain_agent.run \
    --scan data/lab_scans/nmap_host12.xml --scan data/lab_scans/nmap_host13.xml \
    --asset "lab servers" --exposure 8 --criticality 7 --notify
uv run python -m langchain_agent.pdf_report reports/<run_id>.json   # rebuild the PDF
```

- `--scan` can be repeated. Candidate CVEs are chosen in code: top 3 per service by CVSS (same rule as the
  n8n workflow), capped at 16 per run (round-robin by rank, so every service keeps its worst CVE first).
  One ReAct run is made per host. Tool calls are requested in parallel to keep LLM calls low. Any candidate
  the agent skipped gets EPSS, KEV and fuzzy priority from the same tools run in code; those steps are marked
  `(gap fill)` in the trace.
- Host IP, port, PID, service, version and CWEs are filled deterministically from the scan, NVD and the
  host inventory (`vulntriage/inventory.py`), never by the LLM. Findings whose CVE no tool returned are
  dropped. Remediation and references always cite CWE (from NVD) and OWASP WSTG (from `search_knowledge`).
- Host inventory note: a network scan cannot see process ids. The PID comes from "host inventory (lab)",
  built on the Docker host. A real engagement needs host access (authenticated scan or endpoint agent).
- `--notify` sends a Telegram alert (`vulntriage.alerts.format_alert`, pipeline "LangChain agent") for
  critical findings: in KEV, CVSS >= 9, or fuzzy label urgent/high. Alert format per finding:

```
[1/9] CVE-2021-41773
1) Host: 172.30.0.12:80
2) PID: 184072 (host inventory (lab))
3) Service: Apache httpd 2.4.49
4) CVE: CVE-2021-41773
   CVSS: 9.8 | EPSS: 1.000
   In KEV: yes
   CWE: CWE-22
   ATT&CK: T1083 - File and Directory Discovery
   Priority: 88.3/100 (urgent)
5) Fix: Update Apache HTTP Server to version 2.4.51 or later, where path normalization flaws are properly resolved. Ensure configuration options such as Require all denied are strictly enforced for directories outside the web root. Sources: MITRE CWE - CWE-22 Improper Limitation of a Pathname to a Restricted Directory
   Refs: https://cwe.mitre.org/data/definitions/22.html, https://attack.mitre.org/techniques/T1083/, CWE-22: https://cwe.mitre.org/data/definitions/22.html
```

  (first block of the real alert sent by the committed sample run `sample_multihost_gemini`.)
- `reports/<run_id>.pdf` (ReportLab + matplotlib): cover, executive summary, scope and methodology, findings
  table (host IP:port, PID, service, CVE info, recommendation), fuzzy ranking, four charts (severity by
  CVSS band, CVSS vs EPSS by KEV, priority ranking, findings per host), recommendations, and a sources
  appendix. The JSON in `reports/` carries a `meta` block (run id, models, latency) used by the PDF.

### Asset-based prioritization, version source and ranking

- Exposure and criticality come from the asset inventory (`lab/assets.yaml`, `vulntriage.assets.asset_for`)
  per host, not from one global value. `--exposure` and `--criticality` are optional overrides (default:
  use the inventory). The fuzzy priority is computed in code with each host's own values (replacing any value
  the model asked for), so an internal asset never fires an "exposure is internet" rule. Every finding carries
  `asset_name`, `zone`, `exposure`, `criticality` and `version_source`. The PDF scope section states the
  simulated scenario text and a table of the assets in the run.
- Version source: the network scan wins. If it gives no usable `cpe23` and the asset has host-side software
  with a CPE for that port, that CPE selects the candidate CVEs and the finding is labelled
  `version_source: "host inventory (lab)"` (marked `*` in the PDF). Example: lab-host-18 (Spring Framework
  5.3.17) yields CVE-2022-22965. Solr on lab-host-19 does not get Log4Shell, because NVD attaches it to
  log4j and not to Solr; this limitation is not worked around.
- CVSS ties among a service's CVEs are broken by KEV first, then EPSS, so KEV CVEs are not dropped.
- Final ranking tie-break: fuzzy priority, then EPSS, then CVSS, then KEV (all descending).
- The executive summary is built in code (counts by CVSS band, KEV count, top 3 by priority, scenario).
- Every fired fuzzy rule is shown with its activation degree, for example `R1 (0.82): IF cvss is critical
  AND epss is high THEN priority is urgent`, in the markdown report and in PDF section 5.
- PDF layout: the findings table is compact (`#`, host:port, PID, service and version, short CVE info, and
  "See rec. #N"); full recommendations with OWASP/CWE citations and fuzzy reasoning are in section 5, numbered
  to match. Charts are adaptive: with fewer than 3 points or a single category a sentence or small table
  replaces the chart. The CVSS vs EPSS scatter annotates CVE ids and jitters overlapping points.
- `langchain_agent/api.py` keeps working: exposure and criticality in the request body are now optional
  overrides.

## Committed examples (which model produced each)

| Run id | Provider and model | LLM calls | Tokens in/out | Latency (s) | Findings |
|---|---|---|---|---|---|
| `example_nmap_host12_gemini` | Gemini `gemini-3.5-flash-lite` | 8 | 15179 / 1055 | 8.6 | 1 |
| `example_nmap_host14_gemini` | Gemini `gemini-3.5-flash-lite` | 8 | 14961 / 961 | 9.7 | 1 |
| `example_nmap_host12_ollama` | Ollama `qwen2.5:14b`, local GPU | 5 | 8033 / 1135 | 19.0 | 1 |

Latency is wall clock for the whole run (agent loop plus formatting step). `gemini-3.5-flash` itself hit
the free-tier limit of 20 requests per day per model during development, so the examples use the flash-lite
default from `config.py`. `ollama ps` during the Ollama runs printed:

```
NAME           ID              SIZE     PROCESSOR    CONTEXT    RUNNER      UNTIL
qwen2.5:14b    7cdf5a0187d5    15 GB    100% GPU     32768      llamacpp    4 minutes from now
```

Rate-limit behavior observed: Groq `openai/gpt-oss-20b` has an 8000 tokens-per-minute cap that long ReAct
prompts exceed, and it sometimes emits unparseable tool calls (HTTP 400). Both trigger the next provider
in the chain; if every provider fails the chain is retried twice after a 30 to 45 s backoff.

## Trace excerpt (`example_nmap_host12_gemini`)

```
Action: query_nvd {"cpe": "cpe:/a:apache:http_server:2.4.49"}
Observation: {"cpe":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*","top_cves":[{"cve":"CVE-2021-41773","cvss":9.8,"severity":"CRITICAL","cwes":["CWE-22"],"desc":"A flaw was found in a change made to path normalization in Apache 
Action: query_epss {"cve_id": "CVE-2021-41773"}
Observation: {"cve":"CVE-2021-41773","epss":0.99992,"percentile":0.99986}
Action: is_in_kev {"cve_id": "CVE-2021-41773"}
```

Note: Gemini flash-lite usually calls tools without writing the one-sentence Thought the prompt asks for
(the Ollama trace shows Thoughts); Action and Observation are always recorded.

Full traces: `langchain_agent/traces/example_*.md`.
