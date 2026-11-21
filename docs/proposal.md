# Project Proposal: Intelligent Systems Module

**Title:** VulnTriage-AI: An Intelligent Assistant for Vulnerability Triage and Prioritization in Ethical Hacking Engagements

**Instructor:** 
**Program:** Specialization in Artificial Intelligence, Universidad Nacional de Colombia, Sede Manizales
**Team members:**
-  ()
-  ()

---

## 1. Justification

### 1.1 Identified problem
In a pentest or red team engagement, scanning tools (Nmap, Nuclei, OpenVAS) produce hundreds of findings. The analyst must:
- manually review every service and version,
- look up the associated CVEs and their severity,
- decide what to test or report first,
- write the report with evidence and remediation.

This process is slow and error-prone. Prioritizing by CVSS alone is also insufficient: many high-CVSS vulnerabilities are never exploited in practice, while some medium-CVSS ones are.

### 1.2 Proposed solution
A system that takes scan output from an **authorized lab** and does four things:
1. Enriches each finding with public threat intelligence (NVD, EPSS, CISA KEV, MITRE ATT&CK).
2. Prioritizes findings by real-world risk, not just CVSS.
3. Recommends testing methodology and remediation based on OWASP and CWE.
4. Generates a draft pentest report.

### 1.3 Academic relevance
- Workflow automation with AI (n8n).
- LLM agents, tool use, ReAct chain of thought and RAG (LangChain).
- Reasoning under uncertainty with fuzzy logic (rational agent, per Russell & Norvig).
- Quantitative evaluation with ranking and classification metrics.

### 1.4 Ethical and legal scope
- All scanning is performed **exclusively** on assets the team owns and runs locally:
  - intentionally vulnerable containers started on the team's own machine (DVWA, OWASP Juice Shop and Vulhub images with known CVEs),
  - optionally Metasploitable 2 or retired HackTheBox / TryHackMe machines, under their own terms.
- Scans target only the isolated local Docker network or a host-only virtual network. No external host is ever scanned.
- The system **does not run exploits or active scans autonomously**: it only analyzes, prioritizes and recommends. Any active action requires human approval.
- No real IPs, credentials or API keys are published in the repository, the exported workflow or the presentation. Secrets live only in a local `.env` file that is never committed.

---

## 2. Introduction and overall architecture

### 2.1 General objective
Build a vulnerability triage assistant that reduces analysis time and improves prioritization compared to a CVSS-only approach.

### 2.2 Specific objectives
1. Implement the ingestion and enrichment workflow in n8n (Level 1).
2. Reimplement and extend the use case as a ReAct agent with RAG in LangChain (Level 2).
3. Integrate a fuzzy logic engine for risk prioritization and measure its improvement (Level 3).

### 2.3 Overall architecture

```
[Local lab: vulnerable Docker containers] -> Nmap / Nuclei (XML/JSON)
        |
        v
[Ingestion] -> [Parsing] -> [Enrichment: NVD, EPSS, KEV, ATT&CK]
        |
        v
[Reasoning: LLM + RAG (OWASP / CWE / ATT&CK)]
        |
        v
[Prioritization: fuzzy engine]
        |
        v
[Output: Telegram alerts, Postgres findings log, pentest report]
```

### 2.4 Technology choices (all free of charge)

| Component | Choice | Justification |
|---|---|---|
| Workflow engine | n8n Community Edition, self-hosted with Docker | Free, no execution cap, can reach local services. |
| Primary LLM | Google Gemini API, free tier (Flash models) | Strong reasoning and tool calling at no cost; native nodes in n8n and LangChain. |
| Fallback LLMs | Groq free tier; Ollama local model with tool support | Groq adds speed; Ollama keeps working offline, with no quota, and keeps sensitive pentest data on the machine. |
| Embeddings | Gemini embeddings (free tier), local fallback | Used to build the RAG index. |
| Threat intelligence | NVD API 2.0 (free key), FIRST EPSS, CISA KEV, MITRE ATT&CK STIX | Public, authoritative sources. |
| Storage | Postgres (Docker) | Findings log shared by n8n and LangChain. |
| Alerts | Telegram bot | Free and instant. |
| Fuzzy logic | scikit-fuzzy | Standard Python library. |

---

## 3. Level 1: n8n (up to 3.5)

### 3.1 Pipeline (Slide 04)

| Stage | Node(s) | Description |
|---|---|---|
| Trigger | Webhook (POST) | Receives the Nmap XML or Nuclei JSON report. |
| Processing | Code / XML to JSON | Extracts host, port, service, version and CVE. |
| | HTTP Request to NVD API 2.0 | Retrieves CVSS, CWE and description. |
| | HTTP Request to FIRST EPSS API | Retrieves the exploitation probability. |
| | HTTP Request to CISA KEV (JSON) | Checks whether the vulnerability is actively exploited. |
| | AI Agent / LLM (Gemini) | Summarizes the finding and maps it to a MITRE ATT&CK technique. |
| | IF | Separates critical findings (in KEV, or CVSS >= 9) from the rest. |
| Output | Telegram | Sends an immediate alert for critical findings. |
| | Postgres | Logs all enriched findings. |
| | Respond to Webhook | Returns the enriched summary to the caller. |

### 3.2 Metrics to report
- Number of active nodes
- Trigger type: Webhook
- Average execution time per report (s)
- Success rate over at least 20 executions with real lab scans (%)

### 3.3 Step by step (Slide 05)
1. **Access n8n**: self-hosted with Docker (`n8nio/n8n`), stating the version used.
2. **Create the workflow**: `VulnTriage-AI`.
3. **Configure the trigger**: Webhook POST, with a screenshot of its parameters.
4. **Processing nodes**: parsing, NVD, EPSS and KEV calls, LLM and IF.
5. **Output and testing**: Telegram and Postgres, with a manual run using a lab scan.
6. **Activation and monitoring**: workflow set to active, execution history reviewed.

### 3.4 Video and JSON (Slide 06)
- Narrated video of 3 to 8 minutes showing the workflow being built and a real run with a lab scan.
- Exported JSON at `workflow/vulntriage_workflow.json`, **with no credentials or real IPs**.

---

## 4. Level 2: LangChain (up to 4.5)

### 4.1 Architecture (Slide 07)

| Component | Choice | Justification |
|---|---|---|
| LLM | Gemini Flash (free tier), temperature 0.1; configurable fallback to Groq or a local Ollama model | Low temperature gives consistent, auditable output. The local option keeps sensitive engagement data on the machine. |
| ChatPromptTemplate | System: pentest analyst role restricted to authorized assets; Human: `{findings}`, `{asset_context}` | Separates role, data and output format. |
| Tools | `parse_scan`, `query_nvd`, `query_epss`, `is_in_kev`, `search_attack`, `search_knowledge` (RAG) | Each tool provides verifiable data and reduces hallucinations. |
| Agent | ReAct agent (LangGraph `create_react_agent`) | Its Thought, Action, Observation trace is auditable. |

### 4.2 Representative code (Slide 08)

```python
from langchain_core.prompts import ChatPromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI

prompt = ChatPromptTemplate.from_messages([
    ("system",
     "You are a penetration testing analyst working ONLY on authorized assets. "
     "Analyze the findings, query the available tools, "
     "prioritize the risk and propose remediation citing OWASP/CWE. "
     "Never generate exploits."),
    ("human", "Asset: {asset_context}\nFindings:\n{findings}"),
])

llm = ChatGoogleGenerativeAI(model="<gemini-flash-model-id>", temperature=0.1)
# agent = create_react_agent(llm, tools, prompt=...)
```

### 4.3 Chain of thought
- Strategy: **ReAct**.
- Evidence: a real agent log (Thought, Action, Observation) for one lab finding.

### 4.4 Persistence and RAG
- Vector store: **FAISS** or **Chroma**.
- Indexed documents: OWASP Web Security Testing Guide, the CWE catalog and MITRE ATT&CK technique pages.
- Retrieval: semantic similarity with top-k = 4, citing sources in the report.
- Structured output: Pydantic model `Finding` (title, evidence, CVE, risk, ATT&CK technique, remediation).

### 4.5 Video (Slide 09)
- Video of 4 to 6 minutes showing a real run, the agent trace and the generated report.
- Link to the Git repository.

---

## 5. Level 3: Rational technique, Fuzzy Logic (+0.5)

### 5.1 Justification
The risk of a vulnerability is gradual and uncertain: a CVSS of 8.9 and one of 9.0 do not differ in any meaningful way. Fuzzy logic combines several imprecise factors into an explainable priority through rules an analyst can read.

### 5.2 Design (Slide 10)

**Input variables**

| Variable | Universe | Linguistic terms |
|---|---|---|
| CVSS | 0 to 10 | low, medium, high, critical |
| EPSS | 0 to 1 | low, medium, high |
| Exposure | 0 to 10 | internal, DMZ, internet |
| Asset criticality | 0 to 10 | low, medium, high |

**Output variable:** Priority (0 to 100): low, medium, high, urgent.

**Membership functions:** triangular and trapezoidal (scikit-fuzzy).

**IF-THEN rules (base set, extended where coverage requires it)**
1. IF CVSS is critical AND EPSS is high, THEN priority is urgent.
2. IF exposure is internet AND CVSS is high, THEN priority is high.
3. IF criticality is high AND CVSS is medium AND exposure is internet, THEN priority is high.
4. IF exposure is DMZ AND EPSS is medium, THEN priority is medium.
5. IF EPSS is low AND exposure is internal, THEN priority is low.
6. IF CVSS is low AND EPSS is low, THEN priority is low.
7. IF criticality is high AND EPSS is high, THEN priority is urgent.

The rule base is checked for coverage: every combination of input terms must fire at least one rule, otherwise the engine has no output for that region. Missing regions are closed with additional rules, each justified.

**Defuzzification:** centroid.

**Integration:** the fuzzy engine is exposed as the agent tool `prioritize_risk()`. The agent cites the fired rules and their activation degree in the report.

### 5.3 Evaluation (Slide 11)
- **Dataset:** about 200 CVEs from the lab services plus a sample from NVD.
- **Ground truth (proxy):** membership in the CISA KEV catalog, meaning the vulnerability has been exploited in the wild.
- **Comparison:**
  - Baseline (Level 2): ranking by CVSS.
  - Proposed (Level 3): ranking by fuzzy priority.
  - Ablation: fuzzy priority without the EPSS input, to measure how much of the improvement survives without the variable most correlated with KEV.
- **Metrics:** Precision@10, Recall@20, F1 and average response time (ms).
- **Charts:** bar chart comparing the metrics and a heatmap of the fuzzy decision surface (matplotlib).

### 5.4 Critical analysis and limitations
- EPSS and KEV are correlated, which may overstate the improvement (evaluation bias); the ablation quantifies this effect.
- Exposure and asset criticality are assigned manually in the lab.
- Membership functions were defined by expert judgment, not learned from data.

### 5.5 Future improvement
- Tune the membership functions from data (neuro-fuzzy system such as ANFIS).
- Validate priorities against human analysts (Kendall's concordance).
- Orchestrate the full flow with LangGraph, including a human approval node.

---

## 6. Conclusions (Slide 12): to be completed with the results
1. Level 1 (n8n)
2. Level 2 (LangChain)
3. Rational technique
4. Team learnings

---

## 7. Repository structure

```
vulntriage-ai/
├── README.md
├── docker-compose.yml        # n8n + Postgres
├── .env.example              # variable names only, no values
├── workflow/
│   └── vulntriage_workflow.json
├── lab/                      # local vulnerable targets and scan scripts
├── langchain_agent/
│   ├── agent.py
│   ├── tools.py
│   ├── rag_index.py
│   └── prompts.py
├── fuzzy/
│   ├── fuzzy_engine.py
│   └── evaluation.ipynb
├── data/
│   └── lab_scans/            # lab scans only, anonymized
├── docs/
│   ├── proposal.md
│   └── ethical_scope.md
├── tests/
└── pyproject.toml
```

---

## 8. Generative AI use statement
The README and the presentation state which parts were assisted by generative AI (for example: brainstorming the proposal, code drafts, writing) and how they were adapted and verified. Every team member must be able to explain the code and the fuzzy rules during the Q&A session.

---

## 9. References
- n8n Documentation. https://docs.n8n.io
- LangChain Python Docs. https://python.langchain.com/docs/
- NVD API 2.0. https://nvd.nist.gov/developers
- FIRST EPSS. https://www.first.org/epss/
- CISA Known Exploited Vulnerabilities Catalog. https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK. https://attack.mitre.org
- OWASP Web Security Testing Guide. https://owasp.org/www-project-web-security-testing-guide/
- Russell, S. & Norvig, P. (2022). *Artificial Intelligence: A Modern Approach*, 4th ed. Pearson.
- Zadeh, L. A. (1965). Fuzzy sets. *Information and Control*, 8(3), 338-353.
