"""Pydantic output schemas (validated before anything is written to disk)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FiredRule(BaseModel):
    id: str
    text: str = ""
    activation: float | None = None


class Finding(BaseModel):
    # host_ip, port, pid, pid_source, service, version and cwes are filled by the pipeline from
    # the scan, the host inventory and NVD (never by the LLM); leave them null.
    host_ip: str | None = None
    port: int | None = None
    pid: int | None = None
    pid_source: str | None = None
    service: str | None = None
    version: str | None = None
    cwes: list[str] = Field(default_factory=list)
    asset_name: str | None = None
    zone: str | None = None
    exposure: float | None = None
    criticality: float | None = None
    version_source: str | None = None  # "network scan" or "host inventory (lab)"
    title: str = Field(description="Short finding title, e.g. 'Apache httpd 2.4.49 path traversal'")
    evidence: str = Field(description="Scan evidence: host, port, service, version")
    cve: str | None = Field(default=None, description="Most relevant CVE id or null")
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    in_kev: bool | None = None
    priority: float | None = Field(default=None, ge=0, le=100,
                                   description="Fuzzy priority from prioritize_risk")
    label: str | None = Field(default=None, description="Fuzzy label (e.g. Critical)")
    fired_rules: list[FiredRule] = Field(default_factory=list)
    attack_technique: str | None = Field(default=None, description="ATT&CK id and name")
    remediation: str = Field(description="Concrete fix; cite OWASP/CWE sources")
    references: list[str] = Field(default_factory=list, description="Source titles or URLs")


class Report(BaseModel):
    asset: str
    executive_summary: str
    findings: list[Finding]


def rank_key(f: Finding) -> tuple:
    """Ranking: fuzzy priority, then EPSS, then CVSS, then KEV (all descending)."""
    def num(v):
        return -1.0 if v is None else float(v)

    return (-num(f.priority), -num(f.epss), -num(f.cvss), -int(bool(f.in_kev)))


def dedupe_refs(refs: list[str]) -> list[str]:
    """One entry per URL (the first, labelled one wins); entries without a URL kept once."""
    seen: dict[str, str] = {}
    for r in refs:
        key = r[r.index("http"):] if "http" in r else r
        if key not in seen or (seen[key].startswith("http") and not r.startswith("http")):
            seen[key] = r
    return list(seen.values())
