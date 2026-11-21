"""Generate the VulnTriage-AI n8n workflow definition.

The workflow is authored as code so it can be reviewed and regenerated, then
imported into n8n with the CLI. workflow/vulntriage_workflow.json is the file
exported back from the running n8n instance (see workflow/README.md).
API keys are never written here: nodes read them at runtime with $env.

Usage: uv run python workflow/build_workflow.py > workflow/vulntriage_workflow.draft.json
"""

from __future__ import annotations

import json
import sys
import uuid

PG_CREDENTIAL = {"postgres": {"id": "vtPostgres00001", "name": "VulnTriage Postgres"}}

PARSE_JS = r"""
// Parse an Nmap XML (-sV -oX) or Nuclei JSONL report into one item per service.
const body = $input.first().json.body || $input.first().json;
const report = String(body.report || '');
const asset = body.asset || 'lab';
const runId = body.run_id || `n8n-${Date.now()}`;
const cveRe = /CVE-\d{4}-\d{4,}/gi;
const uniq = (a) => [...new Set(a.map((c) => c.toUpperCase()))];

function cpe22to23(c) {
  if (!c || !c.startsWith('cpe:/')) return null;
  const p = c.slice(5).split(':');
  if (p.length < 4 || !p[3]) return null; // a CPE without a version is too broad
  while (p.length < 11) p.push('*');
  return 'cpe:2.3:' + p.slice(0, 11).map((x) => x || '*').join(':');
}

const findings = [];
if (report.trim().startsWith('<')) {
  for (const h of report.match(/<host\b[\s\S]*?<\/host>/g) || []) {
    const addr = (h.match(/<address addr="([^"]+)" addrtype="ipv4"/) || [])[1] || 'unknown';
    const portRe = /<port protocol="(\w+)" portid="(\d+)">([\s\S]*?)<\/port>/g;
    let m;
    while ((m = portRe.exec(h))) {
      const inner = m[3];
      if (!/<state state="open"/.test(inner)) continue;
      const attr = (n) => (inner.match(new RegExp(`<service[^>]*\\s${n}="([^"]*)"`)) || [])[1] || null;
      const cpes = [...inner.matchAll(/<cpe>([^<]+)<\/cpe>/g)].map((x) => x[1]);
      findings.push({
        run_id: runId, asset, host: addr, port: Number(m[2]), service: attr('name'),
        product: attr('product'), version: attr('version'),
        cpe23: cpes.map(cpe22to23).find(Boolean) || null,
        cves: uniq(inner.match(cveRe) || []), source: 'nmap',
      });
    }
  }
} else {
  for (const line of report.split('\n')) {
    if (!line.trim()) continue;
    const it = JSON.parse(line);
    const info = it.info || {};
    let ids = (info.classification || {})['cve-id'] || [];
    if (typeof ids === 'string') ids = [ids];
    findings.push({
      run_id: runId, asset, host: it.ip || it.host || 'unknown',
      port: it.port ? Number(it.port) : null, service: it.type || null,
      product: info.name || it['template-id'], version: null, cpe23: null,
      cves: uniq([...ids, ...((it['template-id'] || '').match(cveRe) || [])]), source: 'nuclei',
    });
  }
}
// Keep only findings that can be linked to CVEs (direct ids or a versioned CPE).
const usable = findings.filter((f) => f.cves.length > 0 || f.cpe23);
if (usable.length === 0) {
  return [{ json: { run_id: runId, asset, host: null, port: null, cves: [], cpe23: null,
    empty: true, parsed_services: findings.length } }];
}
return usable.map((f) => ({ json: { ...f, parsed_services: findings.length } }));
"""

TOP_CVES_JS = r"""
// Keep the 3 highest-CVSS CVEs that NVD reports for the service CPE.
const original = $('Has CVE ids?').item.json;
const vulns = ($input.item.json.vulnerabilities || []).map((v) => {
  const m = v.cve.metrics || {};
  const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
  return { id: v.cve.id, score: metric ? metric.cvssData.baseScore : 0 };
});
vulns.sort((a, b) => b.score - a.score);
return { json: { ...original, cves: vulns.slice(0, 3).map((v) => v.id), cve_source: 'nvd_cpe' } };
"""

SPLIT_JS = r"""
// One item per (host, port, CVE), deduplicated and capped to bound latency.
const MAX_CVES = 12;
const seen = new Set();
const out = [];
for (const item of $input.all()) {
  const f = item.json;
  for (const cve of f.cves || []) {
    const key = `${f.host}:${f.port}:${cve}`;
    if (seen.has(key) || out.length >= MAX_CVES) continue;
    seen.add(key);
    out.push({ json: { run_id: f.run_id, asset: f.asset, host: f.host, port: f.port,
      service: f.service, product: f.product, version: f.version, cve_id: cve } });
  }
}
if (out.length === 0) {
  const f = $input.first().json;
  return [{ json: { no_cves: true, run_id: f.run_id, asset: f.asset,
    parsed_services: f.parsed_services || 0 } }];
}
return out;
"""

COMBINE_JS = r"""
// Join NVD, EPSS and KEV data for each CVE (items keep the same order).
const kevSet = new Set(($input.first().json.vulnerabilities || []).map((v) => v.cveID));
const base = $('One item per CVE').all();
const nvd = $('NVD CVE details').all();
const epss = $('FIRST EPSS').all();
return base.map((b, i) => {
  const f = b.json;
  const v = ((nvd[i] && nvd[i].json.vulnerabilities) || [])[0];
  const cve = v ? v.cve : {};
  const m = cve.metrics || {};
  const metric = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
  const cvss = metric ? metric.cvssData.baseScore : null;
  const desc = ((cve.descriptions || []).find((d) => d.lang === 'en') || {}).value || '';
  const cwes = [...new Set((cve.weaknesses || []).flatMap((w) => w.description)
    .map((d) => d.value).filter((x) => x && x.startsWith('CWE-')))];
  const e = ((epss[i] && epss[i].json.data) || [])[0];
  const epssScore = e ? Number(e.epss) : 0;
  const inKev = kevSet.has(f.cve_id);
  return { json: { ...f, cvss_score: cvss, epss: epssScore, in_kev: inKev, cwes,
    description: desc.slice(0, 400), critical: inKev || (cvss !== null && cvss >= 9) } };
});
"""

PROMPT_JS = r"""
// Build one LLM request for the whole report (one call per execution keeps us in quota).
const findings = $input.all().map((i) => i.json);
const lines = findings.map((f, n) => `${n + 1}. ${f.cve_id} | ${f.product || f.service} ` +
  `${f.version || ''} | CVSS ${f.cvss_score} | EPSS ${f.epss.toFixed(4)} | KEV ${f.in_kev} | ` +
  `${f.cwes.join(',')} | ${f.description}`);
const system = 'You are a penetration testing analyst working ONLY on authorized lab assets. ' +
  'For each finding write a one-sentence risk summary and map it to the single most relevant ' +
  'MITRE ATT&CK Enterprise technique. Never write exploit code. Answer with JSON only: ' +
  '{"executive_summary": str, "findings": [{"cve_id": str, "summary": str, ' +
  '"attack_technique_id": str, "attack_technique_name": str}]}';
return [{ json: { system, user: 'Findings:\n' + lines.join('\n'), findings } }];
"""

PARSE_LLM_JS = r"""
// Accept either a Gemini or a Groq response; degrade gracefully if both failed.
const r = $input.first().json;
let text = null;
let provider = 'none';
if (r.candidates) {
  text = r.candidates[0].content.parts.map((p) => p.text || '').join('');
  provider = 'gemini';
} else if (r.choices) {
  text = r.choices[0].message.content;
  provider = 'groq';
}
let parsed = { executive_summary: 'LLM unavailable: enrichment data only.', findings: [] };
if (text) {
  try {
    parsed = JSON.parse(text.replace(/^```(json)?|```$/gm, '').trim());
  } catch (e) {
    parsed.executive_summary = text.slice(0, 500);
  }
}
const byCve = Object.fromEntries((parsed.findings || []).map((f) => [f.cve_id, f]));
const findings = $('Build LLM prompt').first().json.findings;
return findings.map((f) => {
  const l = byCve[f.cve_id] || {};
  return { json: {
    pipeline: 'n8n', run_id: f.run_id, asset: f.asset, host: f.host, port: f.port,
    service: f.service, product: f.product, version: f.version, cve_id: f.cve_id,
    cvss_score: f.cvss_score, epss: f.epss, in_kev: f.in_kev, cwes: f.cwes.join(','),
    attack_technique: l.attack_technique_id
      ? `${l.attack_technique_id} ${l.attack_technique_name || ''}`.trim() : null,
    critical: f.critical, priority: null, summary: l.summary || null, llm_provider: provider,
    executive_summary: parsed.executive_summary || null,
  } };
});
"""

AGGREGATE_JS = r"""
// Summarize the run and prepare the Telegram alert text for critical findings.
const rows = $('Parse LLM output').all().map((i) => i.json);
const body = $('Receive scan report').first().json.body || {};
const critical = rows.filter((r) => r.critical);
const lines = critical.map((r) => `- ${r.cve_id} on ${r.host}:${r.port} (${r.product || r.service})` +
  ` CVSS ${r.cvss_score}, EPSS ${Number(r.epss).toFixed(3)}${r.in_kev ? ', in CISA KEV' : ''}` +
  `${r.attack_technique ? ', ' + r.attack_technique : ''}`);
const message = `VulnTriage-AI alert (${rows[0].asset}, run ${rows[0].run_id})\n` +
  `${critical.length} critical of ${rows.length} findings:\n${lines.join('\n')}\n\n` +
  `${rows[0].executive_summary || ''}`.slice(0, 3900);
return [{ json: {
  run_id: rows[0].run_id, asset: rows[0].asset, findings: rows.length,
  critical_count: critical.length, notify: body.notify !== false,
  llm_provider: rows[0].llm_provider, executive_summary: rows[0].executive_summary,
  message, results: rows.map(({ executive_summary, ...r }) => r),
} }];
"""


def node(name: str, ntype: str, version: float, pos: tuple[int, int], params: dict,
         **extra) -> dict:
    return {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, "vulntriage/" + name)), "name": name,
            "type": ntype, "typeVersion": version, "position": list(pos),
            "parameters": params, **extra}


def code(name: str, js: str, pos: tuple[int, int], per_item: bool = False) -> dict:
    params = {"jsCode": js.strip()}
    if per_item:
        params["mode"] = "runOnceForEachItem"
    return node(name, "n8n-nodes-base.code", 2, pos, params)


def http(name: str, pos: tuple[int, int], url: str, method: str = "GET",
         query: list | None = None, headers: list | None = None, json_body: str | None = None,
         batch_ms: int | None = None, timeout: int = 60000, **extra) -> dict:
    params: dict = {"method": method, "url": url, "options": {"timeout": timeout}}
    if query:
        params["sendQuery"] = True
        params["queryParameters"] = {"parameters": [{"name": k, "value": v} for k, v in query]}
    if headers:
        params["sendHeaders"] = True
        params["headerParameters"] = {"parameters": [{"name": k, "value": v} for k, v in headers]}
    if json_body:
        params.update({"sendBody": True, "specifyBody": "json", "jsonBody": json_body})
    if batch_ms:
        params["options"]["batching"] = {"batch": {"batchSize": 1, "batchInterval": batch_ms}}
    return node(name, "n8n-nodes-base.httpRequest", 4.2, pos, params, **extra)


def if_node(name: str, pos: tuple[int, int], left: str, operator: dict, right=None) -> dict:
    cond = {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, name)), "leftValue": left,
            "operator": operator}
    if right is not None:
        cond["rightValue"] = right
    return node(name, "n8n-nodes-base.if", 2, pos, {
        "conditions": {"options": {"caseSensitive": True, "typeValidation": "loose"},
                       "conditions": [cond], "combinator": "and"},
        "options": {}})


NVD_HEADERS = [("apiKey", "={{ $env.NVD_API_KEY }}")]
RETRY = {"retryOnFail": True, "maxTries": 3, "waitBetweenTries": 3000}

GEMINI_BODY = (
    "={{ JSON.stringify({ systemInstruction: { parts: [{ text: $json.system }] }, "
    "contents: [{ role: 'user', parts: [{ text: $json.user }] }], "
    "generationConfig: { temperature: 0.1, responseMimeType: 'application/json' } }) }}"
)
GROQ_BODY = (
    "={{ JSON.stringify({ model: $env.VULNTRIAGE_GROQ_MODEL || 'openai/gpt-oss-20b', "
    "temperature: 0.1, response_format: { type: 'json_object' }, messages: ["
    "{ role: 'system', content: $('Build LLM prompt').first().json.system }, "
    "{ role: 'user', content: $('Build LLM prompt').first().json.user }] }) }}"
)
TELEGRAM_BODY = (
    "={{ JSON.stringify({ chat_id: $env.TELEGRAM_CHAT_ID, text: $json.message, "
    "disable_web_page_preview: true }) }}"
)


def build() -> dict:
    nodes = [
        node("Receive scan report", "n8n-nodes-base.webhook", 2, (0, 0), {
            "httpMethod": "POST", "path": "vulntriage", "responseMode": "responseNode",
            "options": {}}, webhookId="5b1d2c7e-6f0a-4c3e-9a51-3d7f2a1e0b01"),
        code("Parse scan report", PARSE_JS, (240, 0)),
        if_node("Has CVE ids?", (480, 0), "={{ $json.cves.length > 0 || $json.empty === true }}",
                {"type": "boolean", "operation": "true", "singleValue": True}),
        http("NVD CPE lookup", (660, 200), "https://services.nvd.nist.gov/rest/json/cves/2.0",
             query=[("virtualMatchString", "={{ $json.cpe23 }}"), ("resultsPerPage", "200")],
             headers=NVD_HEADERS, batch_ms=700, **RETRY),
        code("Top CVEs from CPE", TOP_CVES_JS, (900, 200), per_item=True),
        node("Join CVE sources", "n8n-nodes-base.merge", 3, (1080, 0), {}),
        code("One item per CVE", SPLIT_JS, (1320, 0)),
        if_node("CVEs linked?", (1560, 0), "={{ $json.no_cves !== true }}",
                {"type": "boolean", "operation": "true", "singleValue": True}),
        node("Respond no findings", "n8n-nodes-base.respondToWebhook", 1.1, (1800, 200), {
            "respondWith": "json",
            "responseBody": "={{ JSON.stringify({ run_id: $json.run_id, asset: $json.asset, "
                            "findings: 0, critical_count: 0, parsed_services: $json.parsed_services, "
                            "message: 'No CVE-linked findings in this report' }) }}",
            "options": {}}),
        http("NVD CVE details", (0, 500), "https://services.nvd.nist.gov/rest/json/cves/2.0",
             query=[("cveId", "={{ $json.cve_id }}")], headers=NVD_HEADERS, batch_ms=700,
             **RETRY),
        http("FIRST EPSS", (240, 500), "https://api.first.org/data/v1/epss",
             query=[("cve", "={{ $('One item per CVE').item.json.cve_id }}")], **RETRY),
        http("CISA KEV catalog", (480, 500),
             "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
             executeOnce=True, **RETRY),
        code("Combine intel", COMBINE_JS, (720, 500)),
        code("Build LLM prompt", PROMPT_JS, (960, 500)),
        http("Gemini summarize", (1200, 500),
             "=https://generativelanguage.googleapis.com/v1beta/models/"
             "{{ $env.VULNTRIAGE_GEMINI_MODEL || 'gemini-3.5-flash-lite' }}:generateContent",
             method="POST", headers=[("x-goog-api-key", "={{ $env.GOOGLE_API_KEY }}")],
             json_body=GEMINI_BODY, timeout=90000, retryOnFail=True, maxTries=2,
             waitBetweenTries=5000, onError="continueErrorOutput"),
        http("Groq fallback", (1440, 700), "https://api.groq.com/openai/v1/chat/completions",
             method="POST", headers=[("Authorization", "=Bearer {{ $env.GROQ_API_KEY }}")],
             json_body=GROQ_BODY, timeout=90000, retryOnFail=True, maxTries=3,
             waitBetweenTries=5000, onError="continueRegularOutput"),
        code("Parse LLM output", PARSE_LLM_JS, (1680, 500)),
        node("Log findings to Postgres", "n8n-nodes-base.postgres", 2.5, (0, 1000), {
            "schema": {"__rl": True, "mode": "list", "value": "public"},
            "table": {"__rl": True, "mode": "name", "value": "findings"},
            "columns": {"mappingMode": "defineBelow", "value": {
                c: f"={{{{ $json.{c} }}}}" for c in (
                    "pipeline", "run_id", "asset", "host", "port", "service", "product",
                    "version", "cve_id", "cvss_score", "epss", "in_kev", "cwes",
                    "attack_technique", "critical", "summary", "llm_provider")},
                "matchingColumns": [], "schema": []},
            "options": {}}, credentials=PG_CREDENTIAL),
        code("Aggregate run", AGGREGATE_JS, (240, 1000)),
        if_node("Critical findings? (KEV or CVSS >= 9)", (480, 1000),
                "={{ $json.critical_count > 0 && $json.notify }}",
                {"type": "boolean", "operation": "true", "singleValue": True}),
        http("Telegram alert", (720, 1200),
             "=https://api.telegram.org/bot{{ $env.TELEGRAM_BOT_TOKEN }}/sendMessage",
             method="POST", json_body=TELEGRAM_BODY, onError="continueRegularOutput"),
        node("Respond with triage", "n8n-nodes-base.respondToWebhook", 1.1, (960, 1000), {
            "respondWith": "json",
            "responseBody": "={{ JSON.stringify($('Aggregate run').first().json) }}",
            "options": {}}),
    ]

    def link(*targets: str | tuple[str, int]) -> list:
        return [{"node": t, "type": "main", "index": 0} if isinstance(t, str)
                else {"node": t[0], "type": "main", "index": t[1]} for t in targets]

    connections = {
        "Receive scan report": {"main": [link("Parse scan report")]},
        "Parse scan report": {"main": [link("Has CVE ids?")]},
        "Has CVE ids?": {"main": [link("Join CVE sources"), link("NVD CPE lookup")]},
        "NVD CPE lookup": {"main": [link("Top CVEs from CPE")]},
        "Top CVEs from CPE": {"main": [link(("Join CVE sources", 1))]},
        "Join CVE sources": {"main": [link("One item per CVE")]},
        "One item per CVE": {"main": [link("CVEs linked?")]},
        "CVEs linked?": {"main": [link("NVD CVE details"), link("Respond no findings")]},
        "NVD CVE details": {"main": [link("FIRST EPSS")]},
        "FIRST EPSS": {"main": [link("CISA KEV catalog")]},
        "CISA KEV catalog": {"main": [link("Combine intel")]},
        "Combine intel": {"main": [link("Build LLM prompt")]},
        "Build LLM prompt": {"main": [link("Gemini summarize")]},
        "Gemini summarize": {"main": [link("Parse LLM output"), link("Groq fallback")]},
        "Groq fallback": {"main": [link("Parse LLM output")]},
        "Parse LLM output": {"main": [link("Log findings to Postgres")]},
        "Log findings to Postgres": {"main": [link("Aggregate run")]},
        "Aggregate run": {"main": [link("Critical findings? (KEV or CVSS >= 9)")]},
        "Critical findings? (KEV or CVSS >= 9)": {
            "main": [link("Telegram alert"), link("Respond with triage")]},
        "Telegram alert": {"main": [link("Respond with triage")]},
    }
    return {
        "id": "VulnTriageAI0001",
        "name": "VulnTriage-AI",
        "active": False,
        "nodes": nodes,
        "connections": connections,
        "settings": {"executionOrder": "v1", "saveManualExecutions": True,
                     "saveDataSuccessExecution": "all", "saveDataErrorExecution": "all"},
        "pinData": {},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [],
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=2)
    sys.stdout.write("\n")
