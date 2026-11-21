"""Offline tests for the shared core, the scan tooling and the workflow definition."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.anonymize_scan import anonymize
from vulntriage.intel import CWE_TO_ATTACK, cpe22_to_23, summarize_nvd_cve
from vulntriage.parsers import parse_nmap_xml, parse_nuclei_jsonl, parse_report
from workflow.build_workflow import build

ROOT = Path(__file__).resolve().parent.parent
SCANS = ROOT / "data" / "lab_scans"

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="lab-host-12" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache httpd" version="2.4.49">
<cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports></host></nmaprun>"""

NUCLEI_LINE = json.dumps({
    "template-id": "CVE-2015-5531", "host": "http://lab-host-17:9200", "ip": "lab-host-17",
    "port": "9200", "type": "http",
    "info": {"name": "Elasticsearch Directory Traversal", "severity": "medium",
             "classification": {"cve-id": ["cve-2015-5531"]}},
})


def test_parse_nmap_keeps_only_open_ports():
    findings = parse_nmap_xml(NMAP_XML)
    assert len(findings) == 1
    f = findings[0]
    assert (f["host"], f["port"], f["product"], f["version"]) == (
        "lab-host-12", 80, "Apache httpd", "2.4.49")
    assert f["cpe"] == ["cpe:/a:apache:http_server:2.4.49"]


def test_parse_nuclei_normalizes_cve_ids():
    findings = parse_nuclei_jsonl(NUCLEI_LINE + "\n")
    assert findings[0]["cves"] == ["CVE-2015-5531"]
    assert findings[0]["port"] == 9200
    assert findings[0]["severity"] == "medium"


def test_parse_report_detects_format():
    assert parse_report(NMAP_XML)[0]["source"] == "nmap"
    assert parse_report(NUCLEI_LINE)[0]["source"] == "nuclei"


def test_cpe_conversion_requires_version():
    assert cpe22_to_23("cpe:/a:apache:http_server:2.4.49") == (
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert cpe22_to_23("cpe:/a:samba:samba") is None
    assert cpe22_to_23("not-a-cpe") is None


def test_summarize_nvd_prefers_cvss31():
    raw = {"cve": {"id": "CVE-2021-41773", "descriptions": [{"lang": "en", "value": "Path"}],
                   "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                       "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "AV:N",
                       "attackVector": "NETWORK", "version": "3.1"}}],
                       "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}]},
                   "weaknesses": [{"description": [{"value": "CWE-22"}]}]}}
    s = summarize_nvd_cve(raw)
    assert s["cvss_score"] == 9.8 and s["cvss_version"] == "3.1" and s["cwes"] == ["CWE-22"]


def test_cwe_bridge_points_to_attack_ids():
    assert all(v.startswith("T") for v in CWE_TO_ATTACK.values())


def test_anonymize_replaces_lab_and_private_ips():
    text = 'addr="172.30.0.12" other 192.168.1.20 public 8.8.8.8'
    out = anonymize(text)
    assert "lab-host-12" in out and "lab-host-x" in out
    assert "172.30" not in out and "192.168" not in out and "8.8.8.8" in out


def test_committed_scans_contain_no_lab_ips():
    for path in SCANS.iterdir():
        text = path.read_text()
        assert "172.30." not in text and "192.168." not in text, path.name


def test_workflow_definition_is_consistent():
    wf = build()
    names = {n["name"] for n in wf["nodes"]}
    assert len(names) == len(wf["nodes"])
    for source, conns in wf["connections"].items():
        assert source in names
        for branch in conns["main"]:
            for target in branch:
                assert target["node"] in names
    assert next(n for n in wf["nodes"] if n["type"].endswith(".webhook"))["parameters"][
        "httpMethod"] == "POST"


def test_exported_workflow_has_no_secrets():
    text = (ROOT / "workflow" / "vulntriage_workflow.json").read_text()
    assert "$env.GOOGLE_API_KEY" in text and "$env.TELEGRAM_BOT_TOKEN" in text
    for pattern in ("AIza", "gsk_", "bot1", "bot2", "bot5", "bot6", "bot7", "bot8"):
        assert pattern not in text
