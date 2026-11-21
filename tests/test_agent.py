"""Offline tests for the LangChain agent: no network, no API calls."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from langchain_agent import agent, llm, prompts, tools
from langchain_agent.schemas import Finding, FiredRule, Report
from vulntriage import config, intel

NO_KEYS = {}


def test_provider_chain_default_and_fallbacks():
    chain = llm.provider_chain("gemini", NO_KEYS, have_key=lambda p: True)
    assert chain == ["gemini", "groq"]
    assert llm.provider_chain("groq", NO_KEYS, have_key=lambda p: True) == ["groq", "gemini"]


def test_ollama_has_no_cloud_fallback_by_default():
    assert llm.provider_chain("ollama", NO_KEYS, have_key=lambda p: True) == ["ollama"]


def test_provider_from_env_and_missing_key_skips_fallback():
    env = {"VULNTRIAGE_LLM_PROVIDER": "groq"}
    assert llm.provider_chain(None, env, have_key=lambda p: p != "gemini") == ["groq"]
    env["VULNTRIAGE_LLM_FALLBACKS"] = "ollama,groq"
    assert llm.provider_chain(None, env, have_key=lambda p: True) == ["groq", "ollama"]


def test_unknown_provider_rejected():
    with pytest.raises(ValueError):
        llm.provider_chain("openai", NO_KEYS)


def test_model_ids_follow_config():
    assert llm.model_id("gemini") == config.GEMINI_MODEL
    assert llm.model_id("ollama") == config.OLLAMA_MODEL


def test_prompt_variables_and_roles():
    assert set(prompts.prompt.input_variables) == {"asset_context", "findings"}
    msgs = prompts.prompt.format_messages(asset_context="lab", findings="1. httpd")
    assert msgs[0].type == "system" and "authorized assets" in msgs[0].content
    assert "never" in msgs[0].content.lower() and "exploit" in msgs[0].content.lower()
    assert "lab" in msgs[1].content and "1. httpd" in msgs[1].content


def test_tool_names_match_proposal():
    names = {t.name for t in tools.TOOLS}
    assert {"query_nvd", "query_epss", "is_in_kev", "search_attack", "search_knowledge",
            "prioritize_risk"} <= names and ("parse_scan" in names)


def test_parse_scan_on_lab_data():
    rows = json.loads(tools.parse_scan.invoke({"path": "data/lab_scans/nmap_host12.xml"}))
    assert rows[0]["port"] == 80 and "2.4.49" in rows[0]["version"]


def test_parse_scan_rejects_paths_outside_data():
    out = json.loads(tools.parse_scan.invoke({"path": "pyproject.toml"}))
    assert "error" in out


def test_query_nvd_truncates_and_records_evidence(monkeypatch):
    tools.reset_evidence()
    rec = {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
           "cwes": ["CWE-22"], "description": "x" * 1000}
    monkeypatch.setattr(intel, "nvd_cve", lambda cve: rec)
    out = json.loads(tools.query_nvd.invoke({"cve_id": "CVE-2021-41773"}))
    assert len(out["desc"]) <= tools.DESC_MAX and out["cvss"] == 9.8
    assert tools.EVIDENCE.cves["CVE-2021-41773"]["cvss"] == 9.8


def test_query_nvd_by_cpe_uses_conversion(monkeypatch):
    seen = {}
    monkeypatch.setattr(intel, "nvd_cves_for_cpe",
                        lambda cpe, limit: seen.update(cpe=cpe, limit=limit) or [])
    out = json.loads(tools.query_nvd.invoke({"cpe": "cpe:/a:apache:http_server:2.4.49"}))
    assert seen["cpe"].startswith("cpe:2.3:a:apache:http_server:2.4.49") and out["top_cves"] == []


def test_query_nvd_error_is_returned_not_raised(monkeypatch):
    def boom(cve):
        raise ConnectionError("down")

    monkeypatch.setattr(intel, "nvd_cve", boom)
    assert "error" in json.loads(tools.query_nvd.invoke({"cve_id": "CVE-2021-41773"}))


def test_epss_and_kev_tools(monkeypatch):
    tools.reset_evidence()
    monkeypatch.setattr(intel, "epss_score", lambda c: {"epss": 0.94, "percentile": 0.99})
    monkeypatch.setattr(intel, "kev_entry", lambda c: {
        "dateAdded": "2021-11-03", "knownRansomwareCampaignUse": "Known"})
    assert json.loads(tools.query_epss.invoke({"cve_id": "CVE-2021-41773"}))["epss"] == 0.94
    assert json.loads(tools.is_in_kev.invoke({"cve_id": "CVE-2021-41773"}))["in_kev"] is True
    assert tools.EVIDENCE.cves["CVE-2021-41773"]["in_kev"] is True


def test_search_attack_cwe_bridge(monkeypatch):
    monkeypatch.setattr(intel, "attack_techniques", lambda: [
        {"id": "T1083", "name": "File and Directory Discovery", "tactics": ["discovery"],
         "description": "list files", "url": "u"}])
    out = json.loads(tools.search_attack.invoke({"query": "CWE-22 path traversal"}))
    assert out[0]["id"] == "T1083"


def test_prioritize_risk_wraps_fuzzy_engine(monkeypatch):
    import fuzzy.fuzzy_engine as fe

    tools.reset_evidence()
    fake = {"priority": 88.0, "label": "urgent", "inputs": {},
            "fired_rules": [{"id": "R1", "text": "t", "activation": 1.0}]}
    monkeypatch.setattr(fe, "prioritize", lambda *a, **k: fake)
    out = json.loads(tools.prioritize_risk.invoke(
        {"cvss": 9.8, "epss": 0.9, "exposure": 8, "criticality": 7, "cve_id": "CVE-1-1111"}))
    assert out["label"] == "urgent" and tools.EVIDENCE.priority["CVE-1-1111"] == fake


def test_prioritize_risk_real_engine_returns_rules():
    out = json.loads(tools.prioritize_risk.invoke(
        {"cvss": 9.8, "epss": 0.9, "exposure": 8, "criticality": 7}))
    assert 0 <= out["priority"] <= 100 and out["fired_rules"]


def test_finding_validation():
    with pytest.raises(ValidationError):
        Finding(title="t", evidence="e", remediation="r", cvss=11)
    with pytest.raises(ValidationError):
        Finding(title="t", evidence="e", remediation="r", epss=1.5)
    assert Finding(title="t", evidence="e", remediation="r").fired_rules == []


def _report():
    return Report(asset="lab web", executive_summary="Summary.", findings=[
        Finding(title="low", evidence="e1", cve="CVE-2020-0001", remediation="patch",
                priority=20.0, label="low"),
        Finding(title="Apache path traversal", evidence="80/tcp httpd 2.4.49",
                cve="CVE-2021-41773", cvss=9.8, epss=0.94, in_kev=True, priority=88.3,
                label="urgent", fired_rules=[FiredRule(id="R1", text="IF ...", activation=1.0)],
                attack_technique="T1083 File and Directory Discovery",
                remediation="Upgrade httpd (CWE-22, WSTG-ATHZ-01)",
                references=["OWASP WSTG: Testing Directory Traversal"])])


def test_ground_report_overrides_model_numbers_and_orders():
    tools.reset_evidence()
    tools.EVIDENCE.note("CVE-2021-41773", cvss=7.5, epss=0.5, in_kev=False)
    tools.EVIDENCE.priority["CVE-2021-41773"] = {
        "priority": 70.0, "label": "high",
        "fired_rules": [{"id": "R9", "text": "x", "activation": 0.4}]}
    rep = agent.ground_report(_report())
    top = rep.findings[0]
    assert top.cve == "CVE-2021-41773" and top.cvss == 7.5 and top.in_kev is False
    assert top.priority == 70.0 and top.fired_rules[0].id == "R9"


def test_render_report_markdown():
    trace = {"llm": {"providers_answered": ["gemini-3.5-flash"]}, "latency_s": {"total": 12.3}}
    md = agent.render_report_md(_report(), trace, "run1")
    assert "Executive summary" in md and "| 1 | low |" in md and "R1" in md
    assert "CVE-2021-41773" in md and "WSTG-ATHZ-01" in md


def test_render_trace_markdown_and_steps():
    from langchain_core.messages import AIMessage, ToolMessage

    msgs = [AIMessage(content="I check NVD.", tool_calls=[
                {"name": "query_nvd", "args": {"cve_id": "CVE-1-1"}, "id": "1"}]),
            ToolMessage(content='{"cvss":9.8}', name="query_nvd", tool_call_id="1"),
            AIMessage(content=[{"type": "text", "text": "Final notes."}])]
    steps = agent.steps_from_messages(msgs)
    assert [s["type"] for s in steps] == ["thought", "action", "observation", "final"]
    trace = {"provider_chain": ["gemini"], "llm": {"providers_answered": ["m"], "llm_calls": 2,
             "llm_errors": 0, "input_tokens": 1, "output_tokens": 2},
             "latency_s": {"total": 1}, "steps": steps, "llm_errors": [], "format_error": None}
    md = agent.render_trace_md(trace, "r")
    assert "**Thought:** I check NVD." in md and "**Action:** `query_nvd`" in md
    assert "**Observation:**" in md


def test_trace_callback_summary():
    import uuid

    from langchain_core.messages import AIMessage
    from langchain_core.outputs import ChatGeneration, LLMResult

    cb = llm.TraceCallback()
    rid = uuid.uuid4()
    cb.on_chat_model_start({"id": ["x", "ChatGroq"]}, [], run_id=rid)
    msg = AIMessage(content="hi", response_metadata={"model_name": "openai/gpt-oss-20b"},
                    usage_metadata={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15})
    cb.on_llm_end(LLMResult(generations=[[ChatGeneration(message=msg)]]), run_id=rid)
    s = cb.summary()
    assert s["providers_answered"] == ["openai/gpt-oss-20b"] and s["input_tokens"] == 10
