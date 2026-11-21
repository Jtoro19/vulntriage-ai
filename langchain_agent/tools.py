"""LangChain tools for the ReAct agent. Outputs are compact JSON strings to save tokens.

Tools reuse the cached clients in vulntriage.intel, so reruns do not hit the APIs.
Every verified value is also recorded in EVIDENCE so the final report can be grounded
on tool results instead of on what the model says (see agent.ground_report).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from langchain_core.tools import tool

from vulntriage import intel
from vulntriage.config import ROOT
from vulntriage.parsers import parse_report

DESC_MAX = 220
NVD_TOP = 5


class Evidence:
    """Per-run store of values returned by tools, keyed by CVE id."""

    def __init__(self) -> None:
        self.cves: dict[str, dict] = {}
        self.priority: dict[str, dict] = {}
        self.knowledge: list[dict] = []  # RAG hits seen (source, title, url)

    def note(self, cve: str, **fields) -> None:
        known = self.cves.setdefault(cve.upper(), {})
        known.update({k: v for k, v in fields.items() if v is not None})


EVIDENCE = Evidence()


def reset_evidence() -> None:
    EVIDENCE.cves.clear()
    EVIDENCE.priority.clear()
    EVIDENCE.knowledge.clear()


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _short(text: str | None, n: int = DESC_MAX) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _nvd_row(rec: dict) -> dict:
    EVIDENCE.note(rec["cve_id"], cvss=rec.get("cvss_score"), cwes=rec.get("cwes"))
    return {"cve": rec["cve_id"], "cvss": rec.get("cvss_score"),
            "severity": rec.get("cvss_severity"), "cwes": rec.get("cwes"),
            "desc": _short(rec.get("description"))}


@tool
def parse_scan(path: str) -> str:
    """Parse an Nmap XML or Nuclei JSONL report under the repo data/ folder into findings
    (host, port, service, product, version, cpe, cves). Use only if findings were not given."""
    p = (ROOT / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if not p.is_relative_to(ROOT / "data") or not p.is_file():
        return _dump({"error": "path must be an existing file under data/"})
    rows = parse_report(p.read_text())
    keep = ("host", "port", "service", "product", "version", "cpe", "cves", "title", "severity")
    return _dump([{k: r.get(k) for k in keep if r.get(k) not in (None, [], "")} for r in rows])


@tool
def query_nvd(cve_id: str = "", cpe: str = "") -> str:
    """NVD lookup. Give cve_id (CVE-YYYY-NNNN) for one CVE, or a CPE (Nmap style
    'cpe:/a:apache:http_server:2.4.49' or CPE 2.3) to list the top 5 CVEs by CVSS for that
    product version. Returns cvss, cwes and a short description."""
    try:
        if cve_id:
            rec = intel.nvd_cve(cve_id)
            return _dump(_nvd_row(rec) if rec else {"error": f"{cve_id} not found in NVD"})
        cpe23 = intel.cpe22_to_23(cpe.strip()) if cpe else None
        if not cpe23:
            return _dump({"error": "provide a CVE id or a versioned CPE"})
        rows = intel.nvd_cves_for_cpe(cpe23, limit=NVD_TOP)
        return _dump({"cpe": cpe23, "top_cves": [_nvd_row(r) for r in rows]})
    except Exception as exc:  # network or rate limit: report to the agent, do not crash the run
        return _dump({"error": f"NVD lookup failed: {type(exc).__name__}"})


@tool
def query_epss(cve_id: str) -> str:
    """FIRST EPSS: probability (0 to 1) of exploitation in the next 30 days, and percentile."""
    try:
        r = intel.epss_score(cve_id)
    except Exception as exc:
        return _dump({"error": f"EPSS lookup failed: {type(exc).__name__}"})
    EVIDENCE.note(cve_id, epss=r["epss"])
    return _dump({"cve": cve_id.upper(), "epss": r["epss"], "percentile": r["percentile"]})


@tool
def is_in_kev(cve_id: str) -> str:
    """CISA Known Exploited Vulnerabilities catalog: is the CVE actively exploited in the wild?"""
    try:
        entry = intel.kev_entry(cve_id)
    except Exception as exc:
        return _dump({"error": f"KEV lookup failed: {type(exc).__name__}"})
    EVIDENCE.note(cve_id, in_kev=entry is not None)
    if not entry:
        return _dump({"cve": cve_id.upper(), "in_kev": False})
    return _dump({"cve": cve_id.upper(), "in_kev": True, "date_added": entry["dateAdded"],
                  "ransomware": entry["knownRansomwareCampaignUse"]})


@tool
def search_attack(query: str) -> str:
    """Find MITRE ATT&CK techniques for a weakness or behavior. Query with CWE ids and keywords,
    e.g. 'CWE-22 path traversal'. Returns up to 3 techniques (id, name, tactics, url)."""
    return _dump(intel.search_attack(query, k=3))


@lru_cache(maxsize=1)
def _store():
    from langchain_agent.rag_index import load_index

    return load_index()


@tool
def search_knowledge(query: str) -> str:
    """RAG over the OWASP Web Security Testing Guide, the CWE catalog and ATT&CK (top 4 passages).
    Use it for remediation guidance and to cite sources (source, title, url) in the report."""
    try:
        hits = _store().similarity_search(query, k=4)
    except Exception as exc:
        return _dump({"error": f"knowledge search failed: {type(exc).__name__}"})
    EVIDENCE.knowledge.extend({k: d.metadata.get(k) for k in ("source", "title", "url")}
                              for d in hits)
    return _dump([{"source": d.metadata["source"], "title": d.metadata["title"],
                   "url": d.metadata.get("url"), "text": _short(d.page_content, 350)}
                  for d in hits])


@tool
def prioritize_risk(cvss: float, epss: float, exposure: float, criticality: float,
                    cve_id: str = "") -> str:
    """Fuzzy risk priority (0 to 100) with label and the fuzzy rules fired.
    cvss 0-10, epss 0-1, exposure 0-10 and criticality 0-10 (both given in the asset context).
    Pass cve_id so the result is attached to that finding."""
    from fuzzy.fuzzy_engine import prioritize  # lazy: module is developed separately

    res = prioritize(cvss, epss, exposure, criticality, use_epss=True)
    if cve_id:
        EVIDENCE.priority[cve_id.upper()] = res
        EVIDENCE.note(cve_id, cvss=cvss, epss=epss)
    return _dump({"cve": cve_id.upper() or None, "priority": res["priority"], "label": res["label"],
                  "fired_rules": res["fired_rules"][:5]})


TOOLS = [parse_scan, query_nvd, query_epss, is_in_kev, search_attack, search_knowledge,
         prioritize_risk]
