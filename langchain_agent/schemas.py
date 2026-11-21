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
