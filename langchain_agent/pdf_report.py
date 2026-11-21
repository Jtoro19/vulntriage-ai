"""Professional PDF pentest report (ReportLab + matplotlib) from reports/<run_id>.json.

Usage: uv run python -m langchain_agent.pdf_report reports/<run_id>.json [-o out.pdf]
"""

from __future__ import annotations

import argparse
import io
import json
import math
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
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from langchain_agent.schemas import Finding, Report, dedupe_refs, rank_key  # noqa: E402
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


MIN_POINTS = 3  # never draw a chart with fewer points than this, or with a single category


def chart_decisions(findings: list[Finding]) -> dict[str, str]:
    """For each chart: 'chart' when it is meaningful, else 'text' (a sentence or small table)."""
    scatter = [f for f in findings if f.cvss is not None and f.epss is not None]
    ranked = [f for f in findings if f.priority is not None]
    return {
        "severity": "chart" if len(findings) >= MIN_POINTS
        and len({band(f.cvss) for f in findings}) >= 2 else "text",
        "scatter": "chart" if len(scatter) >= MIN_POINTS else "text",
        "priority": "chart" if len(ranked) >= MIN_POINTS else "text",
        "hosts": "chart" if len(findings) >= MIN_POINTS
        and len({f.host_ip for f in findings}) >= 2 else "text",
    }


def chart_severity(findings: list[Finding]):
    counts = Counter(band(f.cvss) for f in findings)
    names = [b for b in BAND_COLORS if counts.get(b)]
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(names, [counts[b] for b in names], color=[BAND_COLORS[b] for b in names])
    _style(ax, "Severity distribution (CVSS band)")
    ax.set_ylabel("Findings")
    ax.yaxis.get_major_locator().set_params(integer=True)
    return _png(fig)


def jitter(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Deterministic offsets so (nearly) identical points do not hide each other: points that
    fall in the same coarse cell are spread on a small circle around their centre."""
    cell = [(round(x / 0.3), round(y / 0.06)) for x, y in points]
    totals = Counter(cell)
    seen: Counter = Counter()
    out = []
    for (x, y), c in zip(points, cell, strict=True):
        n, k = totals[c], seen[c]
        seen[c] += 1
        if n == 1:
            out.append((x, y))
        else:
            ang = 2 * math.pi * k / n
            out.append((min(10.0, x + 0.3 * math.cos(ang) - 0.2),
                        min(1.0, y + 0.05 * math.sin(ang))))
    return out


# label offsets (points) around a point: alternating radii and directions, with leader lines
_LABEL_OFFSETS = [(30, 18), (-62, 20), (34, -6), (-66, -2), (26, -24), (-58, -24), (12, 34),
                  (-30, 34), (14, -38), (-36, -38)]


def chart_scatter(findings: list[Finding]):
    rows = [f for f in findings if f.cvss is not None and f.epss is not None]
    pts = jitter([(f.cvss, f.epss) for f in rows])
    fig, ax = plt.subplots(figsize=(7.2, 5.4))
    for kev, color, label in ((True, "#e63946", "In CISA KEV"), (False, "#457b9d", "Not in KEV")):
        sel = [p for p, f in zip(pts, rows, strict=True) if bool(f.in_kev) == kev]
        if sel:
            ax.scatter([p[0] for p in sel], [p[1] for p in sel], s=45, color=color,
                       alpha=0.85, label=label, edgecolor="white", zorder=3)
    order = sorted(range(len(pts)), key=lambda i: (round(pts[i][0], 1), pts[i][1]))
    for rank, i in enumerate(order):  # cycle label positions to reduce overlaps
        dx, dy = _LABEL_OFFSETS[rank % len(_LABEL_OFFSETS)]
        ax.annotate(rows[i].cve or "?", pts[i], xytext=(dx, dy), textcoords="offset points",
                    fontsize=5.5, color="#343a40",
                    arrowprops={"arrowstyle": "-", "lw": 0.4, "color": "#adb5bd"})
    _style(ax, "CVSS vs EPSS (overlapping points spread slightly)")
    ax.set_xlabel("CVSS base score")
    ax.set_ylabel("EPSS probability")
    ax.set_xlim(max(0, min(p[0] for p in pts) - 1.0), min(11.5, max(p[0] for p in pts) + 1.4))
    ax.set_ylim(-0.05, 1.25)
    ax.legend(frameon=False, fontsize=8, loc="center left")
    return _png(fig)


def chart_priority(findings: list[Finding]):
    rows = [f for f in findings if f.priority is not None][:15]
    fig, ax = plt.subplots(figsize=(6, max(2.4, 0.32 * len(rows) + 1)))
    ax.barh([_short(f) for f in rows][::-1], [f.priority for f in rows][::-1], color=TEAL)
    ax.set_xlim(0, 100)
    _style(ax, "Fuzzy priority ranking (top 15)")
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


def _text_fallback(name: str, findings: list[Finding], st: dict) -> list:
    """A sentence or a small table replacing a chart that would be degenerate."""
    n = len(findings)
    if name == "severity":
        bands = Counter(band(f.cvss) for f in findings)
        txt = ", ".join(f"{c} {b}" for b, c in bands.items()) or "no findings"
        return [_p(f"Severity distribution: {txt} ({n} findings). A chart is omitted because "
                   "there are fewer than 3 findings or a single severity band.", st["body"])]
    if name == "hosts":
        hosts = sorted({f.host_ip or "unknown" for f in findings})
        return [_p(f"All {n} findings are on {', '.join(hosts) or 'no host'}. A chart is omitted "
                   "because there is a single host or fewer than 3 findings.", st["body"])]
    key = "scatter" if name == "scatter" else "priority"
    rows = [[_p(h, st["head"]) for h in
             (("CVE", "CVSS", "EPSS", "KEV") if key == "scatter"
              else ("CVE", "Host:port", "Priority", "Label"))]]
    for f in findings:
        if key == "scatter":
            rows.append([_p(f.cve or "n/a", st["cell"]), _p(_n(f.cvss, 1), st["cell"]),
                         _p(_n(f.epss, 3), st["cell"]),
                         _p("yes" if f.in_kev else "no", st["cell"])])
        else:
            rows.append([_p(f.cve or "n/a", st["cell"]), _p(f"{f.host_ip}:{f.port}", st["cell"]),
                         _p(_n(f.priority, 1), st["cell"]), _p(f.label or "n/a", st["cell"])])
    title = ("CVSS vs EPSS (table: fewer than 3 points)" if key == "scatter"
             else "Fuzzy priority ranking (table: fewer than 3 findings)")
    return [_p(title, st["h2"]), _table(rows, [4 * cm, 4 * cm, 3 * cm, 3 * cm], st)]


def _n(v, nd: int) -> str:
    return "n/a" if v is None else f"{v:.{nd}f}"


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
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier", fontSize=7.5,
                               leading=9.5),
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


def normalize_obj(obj):
    """Recursively apply the project's punctuation normalization to every string."""
    if isinstance(obj, str):
        return normalize(obj)
    if isinstance(obj, list):
        return [normalize_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize_obj(v) for k, v in obj.items()}
    return obj


def fmt_rule(r) -> str:
    act = f" ({r.activation:.2f})" if r.activation is not None else ""
    return f"{r.id}{act}: {r.text}"


def _service(f: Finding) -> str:
    svc = " ".join(x for x in (f.service, f.version) if x) or "n/a"
    return svc + (" *" if f.version_source == "host inventory (lab)" else "")


def findings_table(findings: list[Finding], st: dict, width: float) -> Table:
    """Compact table; full text lives in the Recommendations section ('See rec. #N')."""
    head = [_p(h, st["head"]) for h in
            ("#", "Host:port", "PID", "Service and version", "CVE information", "Recommendation")]
    rows = [head]
    for i, f in enumerate(findings, 1):
        kev = "yes" if f.in_kev else "no" if f.in_kev is False else "n/a"
        prio = f"{f.priority:.1f} {f.label}" if f.priority is not None else "n/a"
        cve = (f"<b>{escape(f.cve or 'n/a')}</b><br/>CVSS {_n(f.cvss, 1)} | EPSS {_n(f.epss, 3)} | "
               f"KEV {kev}<br/>Priority {escape(prio)}")
        rows.append([_p(i, st["cell"]), Paragraph(f"{escape(f.host_ip or 'n/a')}:{f.port or ''}",
                                                  st["mono"]),
                     _p(f.pid or "n/a", st["cell"]), _p(_service(f), st["cell"]),
                     Paragraph(cve, st["cell"]), _p(f"See rec. #{i}", st["cell"])])
    widths = [0.8 * cm, 3.2 * cm, 1.4 * cm, 3.6 * cm, 5.2 * cm, width - 14.2 * cm]
    return _table(rows, widths, st)


def recommendation_block(i: int, f: Finding, st: dict) -> KeepTogether:
    where = f"{f.host_ip or 'n/a'}:{f.port or ''}"
    asset = f"{f.asset_name or 'n/a'} ({f.zone or 'n/a'} zone)"
    items = [
        _p(f"#{i} {f.cve or f.title} on {where}, {asset}", st["h2"]),
        _p(f"Priority {_n(f.priority, 1)} ({f.label or 'n/a'}); exposure {_n(f.exposure, 0)}, "
           f"criticality {_n(f.criticality, 0)}; version source: "
           f"{f.version_source or 'network scan'}; CWE: {', '.join(f.cwes) or 'n/a'}; "
           f"ATT&CK: {f.attack_technique or 'n/a'}.", st["small"]),
        _p(f.remediation, st["body"])]
    if f.fired_rules:
        items.append(_p("Fuzzy reasoning (rule, activation degree):", st["small"]))
        items += [_p("- " + fmt_rule(r), st["small"]) for r in f.fired_rules]
    return KeepTogether(items)


def assets_table(meta: dict, findings: list[Finding], st: dict) -> Table | None:
    assets = meta.get("assets") or [
        {"host": h, "name": a.asset_name, "zone": a.zone, "exposure": a.exposure,
         "criticality": a.criticality}
        for h, a in {f.host_ip: f for f in findings if f.host_ip}.items()]
    if not assets:
        return None
    rows = [[_p(h, st["head"]) for h in ("Host", "Asset", "Zone", "Exposure", "Criticality")]]
    for a in assets:
        rows.append([_p(a["host"], st["cell"]), _p(a.get("name") or "n/a", st["cell"]),
                     _p(a.get("zone") or "n/a", st["cell"]),
                     _p(_n(a.get("exposure"), 0), st["cell"]),
                     _p(_n(a.get("criticality"), 0), st["cell"])])
    return _table(rows, [3 * cm, 7.4 * cm, 2 * cm, 2.1 * cm, 2.5 * cm], st)


def build_story(data: dict) -> list:
    """Flowables of the whole report (Report fields plus optional "meta")."""
    data = normalize_obj(data)
    report = Report.model_validate(data)
    meta = data.get("meta", {})
    findings = sorted(report.findings, key=rank_key)
    st = _styles()
    w = A4[0] - 4 * cm
    models = ", ".join(meta.get("models") or []) or meta.get("provider", "n/a")
    run_id = meta.get("run_id", "n/a")
    date = meta.get("created", datetime.now().isoformat(timespec="seconds"))[:10]

    story: list = [Spacer(1, 5 * cm), Paragraph(TITLE, st["title"]), Spacer(1, 1 * cm),
                   _p(f"Asset: {report.asset}", st["center"]),
                   _p(f"Date: {date}", st["center"]), _p(f"Run id: {run_id}", st["center"]),
                   Spacer(1, 2.5 * cm),
                   _p(TEAM_LINE, st["center"]),
                   _p(PROGRAM, st["center"]), PageBreak()]

    story += [_p("1. Executive summary", st["h1"]), _p(report.executive_summary, st["body"])]

    story += [_p("2. Scope and methodology", st["h1"]),
              _p("Scope: an isolated Docker lab (private network, no internet exposure) with "
                 "intentionally vulnerable services. Only authorized lab assets were analyzed; "
                 "no exploit was executed.", st["body"])]
    if meta.get("scenario"):
        story += [Spacer(1, 4), _p("Simulated scenario: " + meta["scenario"], st["body"])]
    table = assets_table(meta, findings, st)
    if table is not None:
        story += [Spacer(1, 6), _p("Assets in this run (exposure and criticality, 0 to 10, from "
                                   "the lab asset inventory):", st["small"]), table]
    overrides = {k: v for k, v in (meta.get("overrides") or {}).items() if v is not None}
    story += [Spacer(1, 6)]
    steps = [
        "Discovery: Nmap -sV (service and version detection) and Nuclei templates.",
        "Intelligence: NVD (CVSS, CWE), FIRST EPSS, CISA KEV and MITRE ATT&CK, queried by tools. "
        "Top 3 CVEs per service by CVSS; CVSS ties are broken by KEV first, then EPSS.",
        f"Reasoning: a LangChain/LangGraph ReAct agent (model: {models}) calls the tools and a "
        "RAG index (OWASP WSTG, CWE, ATT&CK) to ground the recommendations.",
        "Prioritization: a fuzzy logic engine combines CVSS, EPSS, and each asset's own exposure "
        "and criticality into a 0 to 100 priority and lists the rules that fired with their "
        "activation degree." + (f" Overrides applied: {overrides}." if overrides else ""),
        "Ranking: fuzzy priority, then EPSS, then CVSS, then KEV (all descending).",
        "PID: taken from \"host inventory (lab)\", built on the Docker host. A network scan "
        "cannot see process ids; a real engagement needs host access through an authenticated "
        "scan or an endpoint agent.",
        "Versions: from the network scan; when it cannot detect one, the version known from the "
        "host side is used and marked with * (version source: host inventory (lab)).",
    ]
    story += [_p("- " + s, st["body"]) for s in steps]

    story += [PageBreak(), _p("3. Findings", st["h1"]),
              _p("Ranked by fuzzy priority, then EPSS, CVSS and KEV. PID source: host inventory "
                 "(lab). * version known only from the host inventory. Full recommendations are "
                 "in section 5.", st["small"]), Spacer(1, 4), findings_table(findings, st, w)]

    story += [PageBreak(), _p("4. Priority ranking and charts", st["h1"])]
    plan = chart_decisions(findings)
    for name, fn in (("severity", chart_severity), ("scatter", chart_scatter),
                     ("priority", chart_priority), ("hosts", chart_hosts)):
        if plan[name] == "chart":
            story += [_image(fn(findings)), Spacer(1, 8)]
        else:
            story += _text_fallback(name, findings, st) + [Spacer(1, 8)]

    story += [PageBreak(), _p("5. Recommendations and fuzzy reasoning", st["h1"])]
    story += [recommendation_block(i, f, st) for i, f in enumerate(findings, 1)]

    story += [PageBreak(), _p("Appendix: sources", st["h1"])]
    story += [Paragraph(f"{escape(n)}: {escape(u)}", st["body"]) for n, u in SOURCES]
    cites = dedupe_refs([r for f in findings for r in f.references])
    if cites:
        story.append(_p("Citations used in this report (RAG and CWE)", st["h2"]))
        story += [_p(c, st["small"]) for c in cites]
    lat = meta.get("latency_s") or {}
    story += [Spacer(1, 10), _p(f"Generated by run {run_id}; models: {models}; "
                                f"total latency {lat.get('total', 'n/a')} s.", st["small"])]

    return story


def build_pdf(data: dict, out: Path) -> Path:
    """Render the report dict to a PDF at `out`."""
    story = build_story(data)
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
