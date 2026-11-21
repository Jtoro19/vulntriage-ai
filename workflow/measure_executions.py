"""Measure the n8n workflow over N real executions with the lab scan reports.

Sends each anonymized report in data/lab_scans/ to the production webhook
(round robin until N executions), then reads the execution records that n8n
stored in Postgres to compute the metrics reported on slide 04:
node count, trigger type, average execution time and success rate.

Usage: uv run python workflow/measure_executions.py --runs 24
Outputs: workflow/metrics/n8n_metrics.json and workflow/metrics/executions.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
SCANS = ROOT / "data" / "lab_scans"
OUT = ROOT / "workflow" / "metrics"
WEBHOOK = "http://localhost:5678/webhook/vulntriage"
WORKFLOW_ID = "VulnTriageAI0001"
ASSETS = {
    "nmap_host10.xml": "lab-dvwa", "nmap_host11.xml": "lab-juice-shop",
    "nmap_host12.xml": "lab-httpd", "nmap_host13.xml": "lab-tomcat",
    "nmap_host14.xml": "lab-drupal", "nmap_host15.xml": "lab-samba",
    "nmap_host16.xml": "lab-jenkins", "nmap_host17.xml": "lab-elasticsearch",
    "nuclei_lab.jsonl": "lab-all-web",
}


def psql(query: str) -> list[list[str]]:
    """Run a read-only query against the n8n database inside the Postgres container."""
    out = subprocess.run(
        ["docker", "exec", "vulntriage-postgres-1", "psql", "-U", "vulntriage", "-d", "n8n",
         "-At", "-F", "\t", "-c", query], check=True, capture_output=True, text=True).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=24)
    parser.add_argument("--notify-every", type=int, default=6,
                        help="send the Telegram alert on every k-th run (others log only)")
    parser.add_argument("--pause", type=float, default=20.0,
                        help="seconds between runs (free-tier LLM quotas are per minute)")
    args = parser.parse_args()

    reports = [p for p in sorted(SCANS.iterdir()) if p.name in ASSETS and p.stat().st_size > 0]
    workflow = json.loads((ROOT / "workflow" / "vulntriage_workflow.json").read_text())
    trigger = next(n for n in workflow["nodes"] if n["type"].endswith(".webhook"))

    start_id = int((psql("select coalesce(max(id), 0) from execution_entity") or [["0"]])[0][0])
    rows = []
    for i in range(args.runs):
        report = reports[i % len(reports)]
        body = {"report": report.read_text(), "asset": ASSETS[report.name],
                "run_id": f"metrics-{i + 1:02d}", "notify": (i % args.notify_every == 0)}
        t0 = time.perf_counter()
        try:
            resp = requests.post(WEBHOOK, json=body, timeout=300)
            status, data = resp.status_code, (resp.json() if resp.content else {})
        except (requests.RequestException, ValueError) as exc:
            status, data = 0, {"error": type(exc).__name__}
        client_s = time.perf_counter() - t0
        rows.append({"run": i + 1, "report": report.name, "http_status": status,
                     "client_seconds": round(client_s, 3), "findings": data.get("findings"),
                     "critical": data.get("critical_count"),
                     "llm_provider": data.get("llm_provider")})
        print(f"run {i + 1:02d} {report.name:18s} HTTP {status} {client_s:6.2f}s "
              f"findings={data.get('findings')} llm={data.get('llm_provider')}")
        time.sleep(args.pause)  # free-tier LLM and NVD quotas

    time.sleep(3)
    execs = psql(
        "select id, status, mode, extract(epoch from (\"stoppedAt\" - \"startedAt\")) "
        f"from execution_entity where id > {start_id} and \"workflowId\" = '{WORKFLOW_ID}' "
        "order by id")
    for row, ex in zip(rows, execs, strict=False):
        row.update({"execution_id": int(ex[0]), "n8n_status": ex[1], "mode": ex[2],
                    "n8n_seconds": round(float(ex[3]), 3) if ex[3] else None})

    durations = [r["n8n_seconds"] for r in rows if r.get("n8n_seconds") is not None]
    ok = [r for r in rows if r.get("n8n_status") == "success" and r["http_status"] == 200]
    with_findings = [r for r in rows if r.get("findings")]
    llm_ok = [r for r in rows if r.get("llm_provider") in ("gemini", "groq")]
    providers = {}
    for r in rows:
        providers[str(r.get("llm_provider"))] = providers.get(str(r.get("llm_provider")), 0) + 1
    metrics = {
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "n8n_version": subprocess.run(["docker", "exec", "vulntriage-n8n-1", "n8n", "--version"],
                                      capture_output=True, text=True).stdout.strip(),
        "workflow": workflow["name"],
        "node_count": len(workflow["nodes"]),
        "trigger": f"{trigger['type'].split('.')[-1]} ({trigger['parameters']['httpMethod']} "
                   f"/webhook/{trigger['parameters']['path']})",
        "executions": len(rows),
        "executions_recorded_by_n8n": len(execs),
        "successful": len(ok),
        "success_rate": round(len(ok) / len(rows), 4) if rows else None,
        "avg_execution_seconds": round(statistics.mean(durations), 3) if durations else None,
        "median_execution_seconds": round(statistics.median(durations), 3) if durations else None,
        "min_execution_seconds": min(durations) if durations else None,
        "max_execution_seconds": max(durations) if durations else None,
        "avg_client_seconds": round(statistics.mean(r["client_seconds"] for r in rows), 3),
        "avg_execution_seconds_with_findings": round(statistics.mean(
            r["n8n_seconds"] for r in with_findings if r.get("n8n_seconds")), 3)
        if with_findings else None,
        "total_findings": sum(r.get("findings") or 0 for r in rows),
        "llm_provider_counts": providers,
        "runs_with_findings": len(with_findings),
        "llm_enriched_runs": len(llm_ok),
        "llm_enriched_rate_of_runs_with_findings": round(len(llm_ok) / len(with_findings), 4)
        if with_findings else None,
        "pause_between_runs_seconds": args.pause,
        "reports_used": [p.name for p in reports],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "n8n_metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    with (OUT / "executions.csv").open("w", newline="") as f:
        fields = list(dict.fromkeys(k for r in rows for k in r))
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
