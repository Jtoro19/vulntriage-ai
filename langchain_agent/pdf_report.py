"""Professional PDF pentest report (ReportLab + matplotlib) from reports/<run_id>.json.

Usage: uv run python -m langchain_agent.pdf_report reports/<run_id>.json [-o out.pdf]
"""

from __future__ import annotations

import argparse
import io
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_CENTER  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: E402
from reportlab.lib.units import cm  # noqa: E402
from reportlab.platypus import (  # noqa: E402
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from langchain_agent.schemas import Finding, Report  # noqa: E402
from vulntriage.text import normalize

TITLE = "VulnTriage-AI Pentest Triage Report"
# No personal names in the repository or its artifacts: the team is listed in the
# course presentation only.
TEAM_LINE = "Team: see the course presentation"
PROGRAM = "Especialización en Inteligencia Artificial, UNAL Sede Manizales"

NAVY, TEAL, GREY, LIGHT = "#1f3a5f", "#2a9d8f", "#6c757d", "#eef2f6"
BAND_COLORS = {"Critical": "#b5179e", "High": "#e63946", "Medium": "#f4a261", "Low": "#2a9d8f",
               "Unknown": "#adb5bd"}
FONT = "Helvetica"

SOURCES = [
    ("NVD API 2.0 (CVSS, CWE)", "https://nvd.nist.gov/developers/vulnerabilities"),
    ("FIRST EPSS", "https://www.first.org/epss/"),
    ("CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("MITRE ATT&CK", "https://attack.mitre.org/"),
    ("OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("MITRE CWE", "https://cwe.mitre.org/"),
]


def band(cvss: float | None) -> str:
    if cvss is None:
        return "Unknown"
    return "Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low"


# ---------------------------------------------------------------- charts


def _png(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf


def _style(ax, title: str) -> None:
    ax.set_title(title, fontsize=11, color=NAVY, fontweight="bold", loc="left")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis="both", alpha=0.25)


def _short(f: Finding, n: int = 34) -> str:
    text = f"{f.cve or f.title} {f.host_ip or ''}:{f.port or ''}"
    return text if len(text) <= n else text[: n - 3] + "..."


def chart_severity(findings: list[Finding]):
    counts = Counter(band(f.cvss) for f in findings)
    names = [b for b in BAND_COLORS if counts.get(b)]
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(names, [counts[b] for b in names], color=[BAND_COLORS[b] for b in names])
    _style(ax, "Severity distribution (CVSS band)")
    ax.set_ylabel("Findings")
    ax.yaxis.get_major_locator().set_params(integer=True)
    return _png(fig)


def chart_scatter(findings: list[Finding]):
    fig, ax = plt.subplots(figsize=(6, 3.4))
    for kev, color, label in ((True, "#e63946", "In CISA KEV"), (False, "#457b9d", "Not in KEV")):
        pts = [(f.cvss, f.epss) for f in findings
               if f.cvss is not None and f.epss is not None and bool(f.in_kev) == kev]
        if pts:
            ax.scatter(*zip(*pts, strict=True), s=55, color=color, alpha=0.85, label=label,
                       edgecolor="white")
    _style(ax, "CVSS vs EPSS")
    ax.set_xlabel("CVSS base score")
    ax.set_ylabel("EPSS probability")
    ax.set_xlim(0, 10.5)
    ax.set_ylim(-0.03, 1.05)
    if ax.get_legend_handles_labels()[0]:
        ax.legend(frameon=False, fontsize=8)
    return _png(fig)


def chart_priority(findings: list[Finding]):
    rows = [f for f in findings if f.priority is not None][:15]
    fig, ax = plt.subplots(figsize=(6, max(2.4, 0.32 * len(rows) + 1)))
    if rows:
        ax.barh([_short(f) for f in rows][::-1], [f.priority for f in rows][::-1], color=TEAL)
    ax.set_xlim(0, 100)
    _style(ax, "Fuzzy priority ranking")
    ax.set_xlabel("Priority (0 to 100)")
    ax.tick_params(axis="y", labelsize=7)
    return _png(fig)


def chart_hosts(findings: list[Finding]):
    counts = Counter(f.host_ip or "unknown" for f in findings)
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(list(counts), list(counts.values()), color=NAVY)
    _style(ax, "Findings per host")
    ax.set_ylabel("Findings")
    ax.tick_params(axis="x", labelsize=7, rotation=30)
    ax.yaxis.get_major_locator().set_params(integer=True)
    return _png(fig)


# ---------------------------------------------------------------- document


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=f"{FONT}-Bold", fontSize=26,
                                textColor=colors.HexColor(NAVY), alignment=TA_CENTER, leading=32),
        "center": ParagraphStyle("c", parent=base["Normal"], fontName=FONT, fontSize=12,
                                 alignment=TA_CENTER, leading=18),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=f"{FONT}-Bold", fontSize=16,
                             textColor=colors.HexColor(NAVY), spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=f"{FONT}-Bold", fontSize=12,
                             textColor=colors.HexColor(TEAL), spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontName=FONT, fontSize=9.5,
                               leading=13.5),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontName=FONT, fontSize=7.5,
                               leading=9.5),
        "head": ParagraphStyle("head", parent=base["BodyText"], fontName=f"{FONT}-Bold",
                               fontSize=8, leading=10, textColor=colors.white),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontName=FONT, fontSize=8,
                                leading=10.5, textColor=colors.HexColor(GREY)),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(normalize(str(text))), style)


def _table(data: list[list], widths: list[float], st: dict) -> Table:
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(NAVY)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(LIGHT)]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#ced4da")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _cve_cell(f: Finding, st) -> Paragraph:
    kev = "yes" if f.in_kev else "no" if f.in_kev is False else "n/a"
    epss = f"{f.epss:.3f}" if f.epss is not None else "n/a"
    prio = f"{f.priority:.1f} ({f.label})" if f.priority is not None else "n/a"
    lines = [f"<b>{escape(f.cve or 'n/a')}</b>",
             f"CVSS {f'{f.cvss:.1f}' if f.cvss is not None else 'n/a'} | EPSS {epss} | KEV {kev}",
             f"CWE: {escape(', '.join(f.cwes) or 'n/a')}",
             f"ATT&amp;CK: {escape(f.attack_technique or 'n/a')}",
             f"Priority: <b>{escape(prio)}</b>"]
    return Paragraph("<br/>".join(lines), st["cell"])


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont(FONT, 8)
    canvas.setFillColor(colors.HexColor(GREY))
    canvas.drawString(2 * cm, 1.2 * cm, "VulnTriage-AI | authorized lab assets only")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _image(buf, width_cm: float = 14.5) -> Image:
    img = Image(buf)
    ratio = img.imageHeight / img.imageWidth
    img.drawWidth, img.drawHeight = width_cm * cm, width_cm * cm * ratio
    return img


def build_pdf(data: dict, out: Path) -> Path:
    """Render the report dict (Report fields plus optional "meta") to `out`."""
    report = Report.model_validate(data)
    meta = data.get("meta", {})
    findings = sorted(report.findings,
                      key=lambda f: -(f.priority if f.priority is not None else -1))
    st = _styles()
    w = A4[0] - 4 * cm
    models = ", ".join(meta.get("models") or []) or meta.get("provider", "n/a")
    run_id = meta.get("run_id", "n/a")
    date = meta.get("created", datetime.now().isoformat(timespec="seconds"))[:10]
    hosts = sorted({f.host_ip for f in findings if f.host_ip})

    story: list = [Spacer(1, 5 * cm), Paragraph(TITLE, st["title"]), Spacer(1, 1 * cm),
                   _p(f"Asset: {report.asset}", st["center"]),
                   _p(f"Date: {date}", st["center"]), _p(f"Run id: {run_id}", st["center"]),
                   Spacer(1, 2.5 * cm),
                   _p(TEAM_LINE, st["center"]),
                   _p(PROGRAM, st["center"]), PageBreak()]

    story += [_p("1. Executive summary", st["h1"]), _p(report.executive_summary, st["body"]),
              Spacer(1, 6)]
    crit = sum(1 for f in findings if band(f.cvss) == "Critical")
    kev = sum(1 for f in findings if f.in_kev)
    story.append(_p(f"{len(findings)} findings on {len(hosts)} host(s); {crit} with CVSS 9.0 or "
                    f"higher; {kev} listed in the CISA KEV catalog.", st["body"]))

    story += [_p("2. Scope and methodology", st["h1"]),
              _p("Scope: an isolated Docker lab (private network, no internet exposure) with "
                 "intentionally vulnerable services. Only authorized lab assets were analyzed; "
                 "no exploit was executed.", st["body"]), Spacer(1, 4)]
    steps = [
        "Discovery: Nmap -sV (service and version detection) and Nuclei templates.",
        "Intelligence: NVD (CVSS, CWE), FIRST EPSS, CISA KEV and MITRE ATT&CK, queried by tools.",
        f"Reasoning: a LangChain/LangGraph ReAct agent (model: {models}) calls the tools and a "
        "RAG index (OWASP WSTG, CWE, ATT&CK) to ground the recommendations.",
        "Prioritization: a fuzzy logic engine combines CVSS, EPSS, exposure and criticality into "
        "a 0 to 100 priority and lists the rules that fired.",
        "PID: taken from \"host inventory (lab)\", built on the Docker host. A network scan "
        "cannot see process ids; a real engagement needs host access through an authenticated "
        "scan or an endpoint agent.",
    ]
    story += [_p("- " + s, st["body"]) for s in steps]

    story += [PageBreak(), _p("3. Findings", st["h1"]),
              _p("Ordered by fuzzy priority (highest first).", st["small"]), Spacer(1, 4)]
    head = [_p(h, st["head"]) for h in
            ("#", "Host IP:port", "PID", "Service", "CVE information", "Recommendation")]
    rows = [head]
    for i, f in enumerate(findings, 1):
        svc = " ".join(x for x in (f.service, f.version) if x) or "n/a"
        pid = f"{f.pid}<br/>({escape(f.pid_source or 'n/a')})" if f.pid else "not found"
        fix = " ".join(f.remediation.split())
        fix = fix if len(fix) <= 330 else fix[:327] + "..."
        rows.append([_p(i, st["cell"]), _p(f"{f.host_ip or 'n/a'}:{f.port or ''}", st["cell"]),
                     Paragraph(pid, st["cell"]), _p(svc, st["cell"]), _cve_cell(f, st),
                     _p(fix, st["cell"])])
    widths = [0.7 * cm, 2.2 * cm, 1.9 * cm, 2.2 * cm, 4.6 * cm, w - 11.6 * cm]
    story.append(_table(rows, widths, st))

    story += [PageBreak(), _p("4. Priority ranking and charts", st["h1"])]
    for fn in (chart_severity, chart_scatter, chart_priority, chart_hosts):
        story += [_image(fn(findings)), Spacer(1, 8)]

    story += [PageBreak(), _p("5. Recommendations", st["h1"])]
    for i, f in enumerate(findings, 1):
        story.append(_p(f"{i}. {f.cve or f.title} on {f.host_ip or 'n/a'}:{f.port or ''}",
                        st["h2"]))
        story.append(_p(f.remediation, st["body"]))
        if f.fired_rules:
            rules = "; ".join(f"{r.id}: {r.text}" for r in f.fired_rules)
            story.append(_p(f"Fuzzy rules fired: {rules}", st["small"]))

    story += [PageBreak(), _p("Appendix: sources", st["h1"])]
    story += [Paragraph(f"{escape(n)}: {escape(u)}", st["body"]) for n, u in SOURCES]
    cites = list(dict.fromkeys(r for f in findings for r in f.references))
    if cites:
        story.append(_p("Citations used in this report (RAG and CWE)", st["h2"]))
        story += [_p(c, st["small"]) for c in cites]
    lat = meta.get("latency_s") or {}
    story += [Spacer(1, 10), _p(f"Generated by run {run_id}; models: {models}; "
                                f"total latency {lat.get('total', 'n/a')} s.", st["small"])]

    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm, title=TITLE,
                            author="VulnTriage-AI")
    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=_footer)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build a PDF from a report JSON")
    ap.add_argument("json_path", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args(argv)
    out = args.output or args.json_path.with_suffix(".pdf")
    build_pdf(json.loads(args.json_path.read_text()), out)
    print(f"pdf: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
