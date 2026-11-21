"""CLI: uv run python -m langchain_agent.run --scan data/lab_scans/nmap_host12.xml
--asset "lab web server" --exposure 8 --criticality 7"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from langchain_agent.agent import render_report_md, render_trace_md, run_agent
from vulntriage import config

TRACE_DIR = config.ROOT / "langchain_agent" / "traces"
REPORT_DIR = config.ROOT / "reports"


def save_to_postgres(report, run_id: str, provider: str, dsn: str) -> int:
    """Optional (needs psycopg, not a default dependency): insert findings, pipeline='langchain'."""
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        for f in report.findings:
            cur.execute(
                "INSERT INTO findings (pipeline, run_id, asset, cve_id, cvss_score, epss, in_kev, "
                "attack_technique, priority, summary, llm_provider) "
                "VALUES ('langchain', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (run_id, report.asset, f.cve, f.cvss, f.epss, f.in_kev, f.attack_technique,
                 f.priority, f.title, provider))
    return len(report.findings)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="VulnTriage Level 2: LangChain ReAct agent")
    ap.add_argument("--scan", required=True, type=Path)
    ap.add_argument("--asset", required=True)
    ap.add_argument("--exposure", type=float, default=5)
    ap.add_argument("--criticality", type=float, default=5)
    ap.add_argument("--provider", help="gemini | groq | ollama (default: env or gemini)")
    ap.add_argument("--run-id")
    ap.add_argument("--db", metavar="DSN", help="also insert findings into Postgres")
    args = ap.parse_args(argv)

    provider = args.provider or config.LLM_PROVIDER
    run_id = args.run_id or f"{datetime.now():%Y%m%d-%H%M%S}_{provider}"
    result = run_agent(args.scan, args.asset, args.exposure, args.criticality, args.provider)
    trace, report = result["trace"], result["report"]

    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (TRACE_DIR / f"{run_id}.json").write_text(json.dumps(trace, indent=2, ensure_ascii=False))
    (TRACE_DIR / f"{run_id}.md").write_text(render_trace_md(trace, run_id))
    print(f"trace:  langchain_agent/traces/{run_id}.md  latency={trace['latency_s']}")
    if report is None:
        print(f"report not produced: {trace['format_error']}", file=sys.stderr)
        return 1
    (REPORT_DIR / f"{run_id}.json").write_text(report.model_dump_json(indent=2))
    (REPORT_DIR / f"{run_id}.md").write_text(render_report_md(report, trace, run_id))
    print(f"report: reports/{run_id}.md  findings={len(report.findings)}")
    if args.db:
        try:
            n = save_to_postgres(report, run_id, provider, args.db)
            print(f"postgres rows inserted: {n}")
        except ImportError:
            print("--db needs psycopg (not a project dependency): uv add 'psycopg[binary]'",
                  file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
