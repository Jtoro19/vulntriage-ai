"""ReAct agent (LangGraph create_react_agent), final structured formatting and report rendering."""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.prebuilt import create_react_agent

from langchain_agent import tools as tools_mod
from langchain_agent.llm import TraceCallback, get_llm, get_structured_llm, provider_chain
from langchain_agent.prompts import FORMAT_SYSTEM, prompt
from langchain_agent.schemas import Finding, FiredRule, Report
from vulntriage import intel
from vulntriage.inventory import load_inventory
from vulntriage.inventory import lookup as inventory_lookup
from vulntriage.parsers import parse_report

RECURSION_LIMIT = 30


# ---------------------------------------------------------------- inputs


PER_SERVICE = 3     # top CVEs per service by CVSS (same rule as the n8n workflow)
MAX_FINDINGS = 12   # cap per run to bound LLM calls


def _cpe23(row: dict) -> str | None:
    """CPE 2.3 match string from the parser ("cpe23"), else converted from the Nmap CPE."""
    if "cpe23" in row:
        return row["cpe23"]
    return next((c23 for c in row.get("cpe") or [] if (c23 := intel.cpe22_to_23(c))), None)


def select_candidates(rows: list[dict], per_service: int = PER_SERVICE,
                      cap: int = MAX_FINDINGS) -> list[dict]:
    """Deterministic candidate CVEs: top `per_service` by CVSS for each service, then capped
    round-robin by rank so that every service keeps its worst CVE before any gets a third."""
    per_row: list[list[dict]] = []
    for row in rows:
        recs: list[dict] = []
        try:
            if row.get("cves"):
                recs = [r for c in row["cves"][:per_service] if (r := intel.nvd_cve(c))]
            elif (cpe23 := _cpe23(row)):
                recs = intel.nvd_cves_for_cpe(cpe23, limit=per_service)
        except Exception:  # NVD unavailable: the service is still reported, without CVEs
            recs = []
        cands = []
        for rec in recs:
            tools_mod._nvd_row(rec)  # records CVSS and CWEs as tool evidence
            cands.append({"cve": rec["cve_id"], "cvss": rec.get("cvss_score"),
                          "cwes": rec.get("cwes") or [], "row": row,
                          "desc": tools_mod._short(rec.get("description"), 110)})
        per_row.append(cands)
    picked: list[dict] = []
    for rank in range(per_service):
        for cands in per_row:
            if rank < len(cands) and len(picked) < cap:
                picked.append(cands[rank])
    return picked


def compact_findings(rows: list[dict], candidates: list[dict] | None = None) -> str:
    """One block per open service, with its candidate CVEs (CVSS, CWE) from NVD."""
    candidates = candidates or []
    lines = []
    for i, r in enumerate(rows, 1):
        lines.append(f"{i}. {r['host']}:{r['port']}/{r['protocol']} service={r['service']} "
                     f"product={r['product']} version={r['version']}")
        mine = [c for c in candidates if c["row"] is r]
        for c in mine:
            lines.append(f"   - {c['cve']} CVSS {c['cvss']} {','.join(c['cwes']) or 'no CWE'}: "
                         f"{c['desc']}")
        if not mine:
            lines.append("   - no candidate CVEs (no versioned CPE or NVD returned none)")
    return "\n".join(lines)


def asset_context(asset: str, exposure: float, criticality: float) -> str:
    return (f"{asset}. Authorized lab asset. exposure={exposure}/10, criticality={criticality}/10 "
            "(use these values when calling prioritize_risk).")


# ---------------------------------------------------------------- agent


def build_agent(provider: str | None = None):
    """Tools are bound on every model of the fallback chain, so a dynamic model callable is used
    (create_react_agent would otherwise try to call bind_tools on the fallback wrapper)."""
    model = get_llm(provider, tools=tools_mod.TOOLS)
    return create_react_agent(lambda state, runtime: model, tools_mod.TOOLS)


def _text(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)


def steps_from_messages(messages: list[BaseMessage]) -> list[dict]:
    """Flatten the message list into Thought / Action / Observation steps."""
    steps = []
    for m in messages:
        if isinstance(m, AIMessage):
            thought = _text(m.content).strip()
            if thought:
                steps.append({"type": "thought" if m.tool_calls else "final", "text": thought})
            for tc in m.tool_calls:
                steps.append({"type": "action", "tool": tc["name"], "args": tc["args"]})
        elif isinstance(m, ToolMessage):
            steps.append({"type": "observation", "tool": m.name, "text": _text(m.content)})
    return steps


def ground_report(report: Report) -> Report:
    """Overwrite numeric fields with values the tools actually returned (anti-hallucination)."""
    ev = tools_mod.EVIDENCE
    for f in report.findings:
        cve = (f.cve or "").upper()
        if cve in ev.cves:
            data = ev.cves[cve]
            f.cvss = data.get("cvss", f.cvss)
            f.epss = data.get("epss", f.epss)
            f.in_kev = data.get("in_kev", f.in_kev)
        if cve in ev.priority:
            pr = ev.priority[cve]
            f.priority, f.label = pr["priority"], pr["label"]
            f.fired_rules = [FiredRule(**r) for r in pr["fired_rules"]]
    report.findings.sort(key=lambda f: -(f.priority if f.priority is not None else -1))
    return report


def enrich_findings(report: Report, candidates: list[dict], inventory: dict) -> Report:
    """Deterministic enrichment (never the LLM): host, port, PID, service, version, CWEs, and
    OWASP/CWE citations. Findings whose CVE is missing or not a listed candidate are dropped."""
    by_cve = {c["cve"]: c["row"] for c in candidates}
    first_row = candidates[0]["row"] if candidates else None
    kept = []
    for f in report.findings:
        cve = (f.cve or "").upper()
        if cve not in by_cve:
            continue  # no CVE, or one the model invented that no tool returned
        row = by_cve.get(cve, first_row)
        if row:
            entry = inventory_lookup(inventory, row["host"], row["port"])
            f.host_ip = entry["ip"] if entry else row["host"]
            f.port = row["port"]
            f.pid = entry["pid"] if entry else None
            f.pid_source = entry["source"] if entry else None
            f.service = row.get("product") or row.get("service")
            f.version = row.get("version")
        f.cwes = tools_mod.EVIDENCE.cves.get(cve, {}).get("cwes") or f.cwes
        _cite(f)
        kept.append(f)
    report.findings = kept
    return report


def _cite(f: Finding) -> None:
    """Make sure remediation and references cite OWASP/CWE, from CWE ids and RAG results."""
    refs = list(f.references)
    for cwe in f.cwes:
        refs.append(f"{cwe}: https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")
    wstg = next((k for k in tools_mod.EVIDENCE.knowledge
                 if k.get("source") == "OWASP WSTG" and k.get("url")), None)
    if wstg:
        refs.append(f"OWASP WSTG {wstg['title']}: {wstg['url']}")
    f.references = list(dict.fromkeys(refs))
    if not re.search(r"CWE-\d+|WSTG|OWASP", f.remediation):
        cited = ", ".join(f.cwes) or (f"OWASP WSTG {wstg['title']}" if wstg else "")
        if cited:
            f.remediation = f"{f.remediation.rstrip()} (sources: {cited})"


def alert_dicts(report: Report) -> list[dict]:
    """Critical findings in the shared alert format (vulntriage.alerts.format_alert)."""
    out = []
    for f in report.findings:
        critical = (f.in_kev or (f.cvss or 0) >= 9
                    or (f.label or "").lower() in ("urgent", "high"))
        if not critical:
            continue
        out.append({
            "host_ip": f.host_ip, "port": f.port, "pid": f.pid, "pid_source": f.pid_source,
            "service": f.service, "version": f.version, "cve_id": f.cve or "CVE n/a",
            "cvss": f.cvss, "epss": f.epss, "in_kev": f.in_kev, "cwes": f.cwes,
            "attack": f.attack_technique, "priority": f.priority, "priority_label": f.label,
            "remediation": " ".join(f.remediation.split())[:420], "references": f.references})
    return out


def fill_gaps(candidates: list[dict], exposure: float, criticality: float) -> list[dict]:
    """Safety net: run the same tools in code for any candidate the agent skipped, so no finding
    lacks EPSS, KEV or a fuzzy priority. The calls are added to the trace as gap fill steps."""
    ev, steps = tools_mod.EVIDENCE, []

    def call(tool, args):
        name = f"{tool.name} (gap fill)"
        steps.append({"type": "action", "tool": name, "args": args})
        steps.append({"type": "observation", "tool": name, "text": tool.invoke(args)})

    for c in candidates:
        cve = c["cve"]
        known = ev.cves.get(cve, {})
        if "epss" not in known:
            call(tools_mod.query_epss, {"cve_id": cve})
        if "in_kev" not in known:
            call(tools_mod.is_in_kev, {"cve_id": cve})
        known = ev.cves.get(cve, {})
        if cve not in ev.priority and known.get("cvss") is not None and "epss" in known:
            call(tools_mod.prioritize_risk, {"cvss": known["cvss"], "epss": known["epss"],
                                             "exposure": exposure, "criticality": criticality,
                                             "cve_id": cve})
    return steps


def _run_host(rows: list[dict], candidates: list[dict], asset: str, exposure: float,
              criticality: float, provider: str | None, cb: TraceCallback) -> dict:
    """ReAct loop plus structured formatting for the services of one host."""
    cfg = {"callbacks": [cb], "recursion_limit": RECURSION_LIMIT}
    msgs = prompt.format_messages(asset_context=asset_context(asset, exposure, criticality),
                                  findings=compact_findings(rows, candidates))
    t0 = time.perf_counter()
    try:
        messages = build_agent(provider).invoke({"messages": msgs}, cfg)["messages"]
        error = None
    except Exception as exc:  # e.g. every provider rate limited: keep the partial trace
        messages, error = [], f"{type(exc).__name__}: {str(exc)[:300]}"
    t_agent = time.perf_counter() - t0
    steps = steps_from_messages(messages) + fill_gaps(candidates, exposure, criticality)
    report, t1 = None, time.perf_counter()
    try:
        if error:
            raise RuntimeError(error)
        notes = _text(messages[-1].content)
        observations = "\n".join(f"[{s['tool']}] {s['text'][:1200]}" for s in steps
                                 if s["type"] == "observation")
        out = get_structured_llm(Report, provider).invoke(
            [SystemMessage(FORMAT_SYSTEM),
             HumanMessage(f"Asset: {asset}\n\nAnalyst notes:\n{notes}\n\nTool observations:\n"
                          f"{observations}")], {"callbacks": [cb]})
        report = ground_report(Report.model_validate(out))
        report.asset = asset
    except Exception as exc:  # keep the trace even if formatting fails
        error = f"{type(exc).__name__}: {str(exc)[:300]}"
    return {"report": report, "steps": steps, "error": error,
            "t_agent": t_agent, "t_format": time.perf_counter() - t1}


def run_agent(scans: list[Path], asset: str, exposure: float, criticality: float,
              provider: str | None = None, inventory: dict | None = None) -> dict:
    """Triage one or more scans (one ReAct run per host). Returns report (or None) and trace."""
    inventory = load_inventory() if inventory is None else inventory
    rows = [r for scan in scans for r in parse_report(Path(scan).read_text())]
    tools_mod.reset_evidence()
    candidates = select_candidates(rows)
    cb = TraceCallback()
    t0 = time.perf_counter()
    reports, steps, errors, t_agent, t_format, hosts = [], [], [], 0.0, 0.0, []
    for host in dict.fromkeys(r["host"] for r in rows):
        host_rows = [r for r in rows if r["host"] == host]
        host_cands = [c for c in candidates if c["row"]["host"] == host]
        hosts.append(host)
        if not host_cands:
            continue  # nothing to triage on this host (no candidate CVEs)
        res = _run_host(host_rows, host_cands, asset, exposure, criticality, provider, cb)
        steps += [{"type": "host", "text": host}] + res["steps"]
        t_agent, t_format = t_agent + res["t_agent"], t_format + res["t_format"]
        if res["error"]:
            errors.append(f"{host}: {res['error']}")
        if res["report"]:
            reports.append((host, enrich_findings(res["report"], host_cands, inventory)))
    report = None
    if reports:
        findings = sorted((f for _, r in reports for f in r.findings),
                          key=lambda f: -(f.priority if f.priority is not None else -1))
        summary = " ".join(f"[{h}] {r.executive_summary}" for h, r in reports)
        report = Report(asset=asset, executive_summary=summary, findings=findings)
    trace = {
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "scans": [str(s) for s in scans], "asset": asset, "exposure": exposure,
        "criticality": criticality, "hosts": hosts, "candidates": len(candidates),
        "provider_chain": provider_chain(provider),
        "llm": cb.summary(), "llm_calls": cb.calls, "llm_errors": cb.errors,
        "latency_s": {"agent": round(t_agent, 1), "format": round(t_format, 1),
                      "total": round(time.perf_counter() - t0, 1)},
        "steps": steps, "format_error": "; ".join(errors) or None,
    }
    return {"report": report, "trace": trace}


# ---------------------------------------------------------------- rendering


def _fmt(v, nd=2):
    return "n/a" if v is None else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


def render_report_md(report: Report, trace: dict, run_id: str) -> str:
    llm = trace["llm"]
    out = [f"# Pentest report draft: {report.asset}", "",
           f"Run `{run_id}`. Models that answered: "
           f"{', '.join(llm['providers_answered']) or 'n/a'}. "
           f"Total latency {trace['latency_s']['total']} s. Draft for analyst review; "
           "authorized assets only.", "",
           "## Executive summary", "", report.executive_summary, "",
           "## Findings (ordered by fuzzy priority)", "",
           "| # | Host:port | PID | Service | CVE | CVSS | EPSS | KEV | Priority | Label |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(report.findings, 1):
        svc = " ".join(x for x in (f.service, f.version) if x) or "n/a"
        out.append(f"| {i} | {f.host_ip or 'n/a'}:{f.port or ''} | {f.pid or 'n/a'} | {svc} "
                   f"| {f.cve or 'n/a'} | {_fmt(f.cvss, 1)} | {_fmt(f.epss, 3)} "
                   f"| {'yes' if f.in_kev else 'no' if f.in_kev is False else 'n/a'} "
                   f"| {_fmt(f.priority, 1)} | {f.label or 'n/a'} |")
    for i, f in enumerate(report.findings, 1):
        out += ["", f"## Finding {i}: {f.title}", "", f"- Evidence: {f.evidence}",
                f"- PID: {f.pid or 'not found'} ({f.pid_source or 'no inventory entry'})",
                f"- CWE: {', '.join(f.cwes) or 'n/a'}",
                f"- ATT&CK: {f.attack_technique or 'n/a'}", "- Fuzzy rules fired:"]
        out += [f"  - {r.id}: {r.text}" + (f" (activation {r.activation:.2f})"
                                           if r.activation is not None else "")
                for r in f.fired_rules] or ["  - none recorded"]
        out += ["", f"Remediation: {f.remediation}"]
        if f.references:
            out += ["", "References:"] + [f"- {r}" for r in f.references]
    return "\n".join(out) + "\n"


def render_trace_md(trace: dict, run_id: str) -> str:
    llm = trace["llm"]
    out = [f"# ReAct trace `{run_id}`", "",
           f"- Provider chain: {' -> '.join(trace['provider_chain'])}",
           f"- Models that answered: {', '.join(llm['providers_answered']) or 'n/a'}",
           f"- LLM calls: {llm['llm_calls']} (errors/fallbacks: {llm['llm_errors']})",
           f"- Tokens in/out: {llm['input_tokens']}/{llm['output_tokens']}",
           f"- Latency (s): {trace['latency_s']}", ""]
    n = 0
    for s in trace["steps"]:
        if s["type"] == "host":
            out += [f"# Host {s['text']}", ""]
            n = 0
        elif s["type"] == "thought":
            n += 1
            out += [f"## Step {n}", "", f"**Thought:** {s['text']}", ""]
        elif s["type"] == "action":
            if not n:
                n += 1
                out += [f"## Step {n}", ""]
            out += [f"**Action:** `{s['tool']}` {json.dumps(s['args'], ensure_ascii=False)}", ""]
        elif s["type"] == "observation":
            out += ["**Observation:**", "", "```", s["text"][:1200], "```", ""]
        else:
            out += ["## Final analysis", "", s["text"], ""]
    if llm["llm_errors"]:
        out += ["## LLM errors (fallback triggers)", ""] + [
            f"- {e['class']}: {e['error']}" for e in trace["llm_errors"]]
    if trace["format_error"]:
        out += ["", f"Formatting error: {trace['format_error']}"]
    return "\n".join(out) + "\n"
