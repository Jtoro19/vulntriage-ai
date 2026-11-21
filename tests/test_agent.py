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
    assert "Executive summary" in md and "CVE-2020-0001" in md and "R1" in md
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


# ---------------------------------------------------------------- inventory, alerts, PDF

INV = {"lab-host-12:80": {"ip": "172.30.0.12", "port": 80, "pid": 4321,
                          "source": "host inventory (lab)"}}
ROW = {"host": "lab-host-12", "port": 80, "protocol": "tcp", "service": "http",
       "product": "Apache httpd", "version": "2.4.49", "cpe": ["cpe:/a:apache:http_server:2.4.49"],
       "cves": []}


def _cands():
    return [{"cve": "CVE-2021-41773", "cvss": 9.8, "cwes": ["CWE-22"], "row": ROW, "desc": "d"}]


def test_select_candidates_top3_round_robin_and_cap(monkeypatch):
    def recs(cpe, limit):
        return [{"cve_id": f"CVE-2020-{i}", "cvss_score": 9 - i, "cwes": [], "description": "x"}
                for i in range(limit)]

    monkeypatch.setattr(intel, "nvd_cves_for_cpe", recs)
    rows = [{**ROW, "port": 80 + i} for i in range(3)]
    out = agent.select_candidates(rows, per_service=3, cap=4)
    assert len(out) == 4
    assert [c["row"]["port"] for c in out] == [80, 81, 82, 80]  # one per service before a 2nd
    assert len(agent.select_candidates(rows, per_service=3, cap=12)) == 9


def test_enrich_findings_uses_inventory_and_drops_invented_cves():
    tools.reset_evidence()
    tools.EVIDENCE.note("CVE-2021-41773", cwes=["CWE-22"])
    rep = Report(asset="a", executive_summary="s", findings=[
        Finding(title="t", evidence="e", cve="CVE-2021-41773", remediation="Upgrade httpd."),
        Finding(title="fake", evidence="e", cve="CVE-1999-0001", remediation="x")])
    out = agent.enrich_findings(rep, _cands(), INV)
    assert len(out.findings) == 1
    f = out.findings[0]
    assert (f.host_ip, f.port, f.pid) == ("172.30.0.12", 80, 4321)
    assert f.pid_source == "host inventory (lab)" and f.service == "Apache httpd"
    assert f.version == "2.4.49" and f.cwes == ["CWE-22"]
    assert "CWE-22" in f.remediation  # citation appended deterministically
    assert any("cwe.mitre.org/data/definitions/22" in r for r in f.references)


def test_enrich_without_inventory_entry_keeps_scan_host():
    tools.reset_evidence()
    rep = Report(asset="a", executive_summary="s", findings=[
        Finding(title="t", evidence="e", cve="CVE-2021-41773", remediation="Fix per OWASP.")])
    f = agent.enrich_findings(rep, _cands(), {}).findings[0]
    assert f.host_ip == "lab-host-12" and f.pid is None and f.pid_source is None


def test_alert_dicts_only_critical_and_alert_labels_in_order():
    from vulntriage.alerts import format_alert

    crit = Finding(title="a", evidence="e", cve="CVE-1-1", cvss=9.8, remediation="r",
                   host_ip="172.30.0.12", port=80, pid=4321, service="Apache", version="2.4.49",
                   pid_source="host inventory (lab)", label="urgent", priority=88.0)
    kev = Finding(title="b", evidence="e", cve="CVE-1-2", cvss=5.0, in_kev=True, remediation="r")
    low = Finding(title="c", evidence="e", cve="CVE-1-3", cvss=3.0, label="low", remediation="r")
    rep = Report(asset="a", executive_summary="s", findings=[crit, kev, low])
    items = agent.alert_dicts(rep)
    assert [i["cve_id"] for i in items] == ["CVE-1-1", "CVE-1-2"]
    text = "\n".join(format_alert(items, "lab", "run1", "LangChain agent"))
    positions = [text.index(label) for label in
                 ("1) Host:", "2) PID:", "3) Service:", "4) CVE:", "5) Fix:")]
    assert positions == sorted(positions)
    assert "172.30.0.12:80" in text and "4321 (host inventory (lab))" in text


def _fixture_report(n: int = 14) -> dict:
    findings = [Finding(
        title=f"Finding {i}", evidence="e", cve=f"CVE-2021-{1000 + i}", cvss=9.8 - i * 0.5,
        epss=0.9 - i * 0.05, in_kev=i % 2 == 0, priority=90.0 - i * 4, label="urgent",
        host_ip=f"172.30.0.{10 + i % 3}", port=80 + i, pid=1000 + i,
        pid_source="host inventory (lab)", service="Apache httpd", version="2.4.49",
        cwes=["CWE-22"], attack_technique="T1083 File and Directory Discovery",
        remediation="Upgrade the package and restrict paths, see CWE-22 and OWASP WSTG. " * 4,
        references=["CWE-22: https://cwe.mitre.org/data/definitions/22.html"],
        fired_rules=[FiredRule(id="R1", text="IF cvss is critical THEN urgent")])
        for i in range(n)]
    rep = Report(asset="lab & <web> servers", executive_summary="Summary & <b>text</b>.",
                 findings=findings)
    return {**rep.model_dump(), "meta": {
        "run_id": "fixture", "created": "2026-11-21T10:00:00", "provider": "gemini",
        "models": ["gemini-3.5-flash-lite"], "latency_s": {"total": 12.0}}}


def test_pdf_builds_from_fixture(tmp_path):
    import re

    from langchain_agent.pdf_report import build_pdf

    out = build_pdf(_fixture_report(), tmp_path / "r.pdf")
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF")
    assert len(re.findall(rb"/Type\s*/Page(?!s)", raw)) > 1


def test_pdf_cli_from_json(tmp_path):
    from langchain_agent.pdf_report import main

    src = tmp_path / "r.json"
    src.write_text(json.dumps(_fixture_report(2)))
    assert main([str(src)]) == 0 and (tmp_path / "r.pdf").read_bytes().startswith(b"%PDF")


def test_pdf_handles_empty_findings(tmp_path):
    from langchain_agent.pdf_report import build_pdf

    data = {"asset": "x", "executive_summary": "none", "findings": []}
    assert build_pdf(data, tmp_path / "e.pdf").read_bytes().startswith(b"%PDF")


def test_fill_gaps_calls_missing_tools_only(monkeypatch):
    import fuzzy.fuzzy_engine as fe

    tools.reset_evidence()
    tools.EVIDENCE.note("CVE-2021-41773", cvss=9.8, epss=0.9, in_kev=True)  # agent did these
    tools.EVIDENCE.note("CVE-2021-42013", cvss=9.8)  # agent skipped this one
    monkeypatch.setattr(intel, "epss_score", lambda c: {"epss": 0.5, "percentile": 0.9})
    monkeypatch.setattr(intel, "kev_entry", lambda c: None)
    monkeypatch.setattr(fe, "prioritize", lambda *a, **k: {
        "priority": 70.0, "label": "high", "inputs": {}, "fired_rules": []})
    cands = [{"cve": "CVE-2021-41773"}, {"cve": "CVE-2021-42013"}]
    steps = agent.fill_gaps(cands, 8, 7)
    called = [(s["tool"], s["args"]["cve_id"]) for s in steps if s["type"] == "action"]
    assert called == [("prioritize_risk (gap fill)", "CVE-2021-41773"),
                      ("query_epss (gap fill)", "CVE-2021-42013"),
                      ("is_in_kev (gap fill)", "CVE-2021-42013"),
                      ("prioritize_risk (gap fill)", "CVE-2021-42013")]
    assert tools.EVIDENCE.priority["CVE-2021-42013"]["label"] == "high"
