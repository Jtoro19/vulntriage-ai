"""Minimal local HTTP bridge so the n8n workflow can trigger the LangChain pipeline.

POST /triage with JSON {"report": "<nmap xml or nuclei jsonl>", "asset": "...",
"exposure": 8, "criticality": 7, "run_id": "..."} runs the agent on the report,
writes reports/<run_id>.md|json|pdf and sends the PDF to Telegram as a document.
It returns {"run_id", "findings", "pdf", "telegram_message_id"}.

It binds to the Docker bridge gateway (172.17.0.1 by default) so only local
containers (n8n) and this host can reach it; it is never exposed on the LAN.
Usage: uv run python -m langchain_agent.api [--host 172.17.0.1] [--port 8765]
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from langchain_agent import run as agent_run
from vulntriage import config
from vulntriage.alerts import send_telegram_document

MAX_BODY = 5_000_000


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        self._reply(200 if self.path == "/health" else 404, {"ok": self.path == "/health"})

    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        if self.path != "/triage":
            return self._reply(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= MAX_BODY:
            return self._reply(413, {"error": "empty or too large"})
        try:
            data = json.loads(self.rfile.read(length))
            report = str(data["report"])
        except (ValueError, KeyError):
            return self._reply(400, {"error": "JSON body with a 'report' field is required"})
        run_id = re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("run_id") or "")) \
            or f"n8n_pdf_{int(time.time())}"
        suffix = ".xml" if report.lstrip().startswith("<") else ".jsonl"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as tmp:
            tmp.write(report)
        argv = ["--scan", tmp.name, "--asset", str(data.get("asset") or "lab"),
                "--exposure", str(data.get("exposure", 8)),
                "--criticality", str(data.get("criticality", 7)), "--run-id", run_id]
        try:
            code = agent_run.main(argv)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        pdf = config.ROOT / "reports" / f"{run_id}.pdf"
        saved = config.ROOT / "reports" / f"{run_id}.json"
        findings = len(json.loads(saved.read_text())["findings"]) if saved.exists() else 0
        msg_id = None
        if pdf.exists() and data.get("send_pdf", True):
            msg_id = send_telegram_document(
                str(pdf), f"VulnTriage-AI triage report ({data.get('asset') or 'lab'}), "
                          f"run {run_id}: {findings} findings ranked by fuzzy priority.")
        self._reply(200 if code == 0 else 500, {
            "run_id": run_id, "findings": findings, "exit_code": code,
            "pdf": str(pdf.relative_to(config.ROOT)) if pdf.exists() else None,
            "telegram_message_id": msg_id})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="172.17.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print(f"VulnTriage-AI pipeline bridge on http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
