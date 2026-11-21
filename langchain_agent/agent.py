"""ReAct agent (LangGraph create_react_agent), final structured formatting and report rendering."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.prebuilt import create_react_agent

from langchain_agent import tools as tools_mod
from langchain_agent.llm import TraceCallback, get_llm, get_structured_llm, provider_chain
from langchain_agent.prompts import FORMAT_SYSTEM, prompt
from langchain_agent.schemas import FiredRule, Report
from vulntriage.parsers import parse_report

RECURSION_LIMIT = 30


# ---------------------------------------------------------------- inputs


def compact_findings(rows: list[dict]) -> str:
    """One line per open service, with the CPE the NVD tool needs."""
    lines = []
    for i, r in enumerate(rows, 1):
        cpe = (r.get("cpe") or [""])[0]
        lines.append(f"{i}. {r['host']}:{r['port']}/{r['protocol']} service={r['service']} "
                     f"product={r['product']} version={r['version']} cpe={cpe} "
                     f"cves_in_scan={r['cves'] or 'none'}")
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


def run_agent(scan: Path, asset: str, exposure: float, criticality: float,
              provider: str | None = None) -> dict:
    """Run the full pipeline. Returns report (or None), trace dict and timings."""
    rows = parse_report(scan.read_text())
    tools_mod.reset_evidence()
    cb = TraceCallback()
    cfg = {"callbacks": [cb], "recursion_limit": RECURSION_LIMIT}
    msgs = prompt.format_messages(asset_context=asset_context(asset, exposure, criticality),
                                  findings=compact_findings(rows))
    t0 = time.perf_counter()
    try:
        messages = build_agent(provider).invoke({"messages": msgs}, cfg)["messages"]
        agent_error = None
    except Exception as exc:  # e.g. every provider rate limited: keep the partial trace
        messages, agent_error = [], f"{type(exc).__name__}: {str(exc)[:300]}"
    t_agent = time.perf_counter() - t0
    steps = steps_from_messages(messages)

    notes = _text(messages[-1].content) if messages else ""
    observations = "\n".join(f"[{s['tool']}] {s['text'][:1500]}" for s in steps
                             if s["type"] == "observation")
    report, error = None, agent_error
    t1 = time.perf_counter()
    try:
        if agent_error:
            raise RuntimeError(agent_error)
        out = get_structured_llm(Report, provider).invoke(
            [SystemMessage(FORMAT_SYSTEM),
             HumanMessage(f"Asset: {asset}\n\nAnalyst notes:\n{notes}\n\nTool observations:\n"
                          f"{observations}")], {"callbacks": [cb]})
        report = ground_report(Report.model_validate(out))
        report.asset = asset
    except Exception as exc:  # keep the trace even if formatting fails
        error = f"{type(exc).__name__}: {str(exc)[:300]}"
    t_format = time.perf_counter() - t1

    trace = {
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "scan": str(scan), "asset": asset, "exposure": exposure, "criticality": criticality,
        "provider_chain": provider_chain(provider),
        "llm": cb.summary(), "llm_calls": cb.calls, "llm_errors": cb.errors,
        "latency_s": {"agent": round(t_agent, 1), "format": round(t_format, 1),
                      "total": round(time.perf_counter() - t0, 1)},
        "steps": steps, "format_error": error,
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
           "| # | Finding | CVE | CVSS | EPSS | KEV | Priority | Label |",
           "|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(report.findings, 1):
        out.append(f"| {i} | {f.title} | {f.cve or 'n/a'} | {_fmt(f.cvss, 1)} | {_fmt(f.epss, 3)} "
                   f"| {'yes' if f.in_kev else 'no' if f.in_kev is False else 'n/a'} "
                   f"| {_fmt(f.priority, 1)} | {f.label or 'n/a'} |")
    for i, f in enumerate(report.findings, 1):
        out += ["", f"## Finding {i}: {f.title}", "", f"- Evidence: {f.evidence}",
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
        if s["type"] == "thought":
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
