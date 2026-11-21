"""Telegram alert format shared by the LangChain pipeline (n8n uses the same layout in JS).

Every finding is rendered in this order, with short labeled lines for a phone:
1) host IP and port, 2) PID (from the host inventory), 3) service and version,
4) CVE information (CVSS, EPSS, KEV, CWE, ATT&CK, fuzzy priority when available),
5) recommendations citing OWASP/CWE.
"""

from __future__ import annotations

import requests

from vulntriage.config import secret
from vulntriage.inventory import SOURCE_LABEL

TELEGRAM_LIMIT = 4000  # Telegram allows 4096 characters per message


def _num(value, fmt: str, default: str = "n/a") -> str:
    return format(value, fmt) if isinstance(value, int | float) else default


def format_finding(f: dict, index: int, total: int) -> str:
    """Render one finding with the five required fields."""
    host = f.get("host_ip") or f.get("host") or "unknown"
    port = f.get("port")
    pid = f.get("pid")
    pid_line = f"{pid} ({f.get('pid_source') or SOURCE_LABEL})" if pid else "not found"
    service = " ".join(str(x) for x in (f.get("service"), f.get("version")) if x) or "unknown"
    cwes = f.get("cwes") or []
    cwe = ", ".join(cwes) if isinstance(cwes, list) else str(cwes)
    priority = f.get("priority")
    prio = (f"{priority:.1f}/100 ({f.get('priority_label')})"
            if isinstance(priority, int | float) else "n/a (fuzzy engine not run)")
    kev = "yes" if f.get("in_kev") else "no"
    fix = (f.get("remediation") or "Review vendor advisory and patch.").strip()
    refs = f.get("references") or []
    ref_line = f"\n   Refs: {', '.join(refs[:3])}" if refs else ""
    return (
        f"[{index}/{total}] {f.get('cve_id', 'CVE n/a')}\n"
        f"1) Host: {host}{':' + str(port) if port else ''}\n"
        f"2) PID: {pid_line}\n"
        f"3) Service: {service}\n"
        f"4) CVE: {f.get('cve_id', 'n/a')}\n"
        f"   CVSS: {_num(f.get('cvss'), '.1f')} | EPSS: {_num(f.get('epss'), '.3f')}\n"
        f"   In KEV: {kev}\n"
        f"   CWE: {cwe or 'n/a'}\n"
        f"   ATT&CK: {f.get('attack') or 'n/a'}\n"
        f"   Priority: {prio}\n"
        f"5) Fix: {fix}{ref_line}"
    )


def format_alert(findings: list[dict], asset: str, run_id: str, pipeline: str) -> list[str]:
    """Header plus one block per finding, split into Telegram-sized messages."""
    header = (f"VulnTriage-AI alert ({pipeline})\nAsset: {asset}\nRun: {run_id}\n"
              f"Critical findings: {len(findings)}")
    blocks = [format_finding(f, i + 1, len(findings)) for i, f in enumerate(findings)]
    messages, current = [], header
    for block in blocks:
        candidate = f"{current}\n\n{block}"
        if len(candidate) > TELEGRAM_LIMIT:
            messages.append(current)
            current = block[:TELEGRAM_LIMIT]
        else:
            current = candidate
    messages.append(current)
    return messages


def send_telegram(messages: list[str]) -> list[int]:
    """Send messages to the configured chat. Returns the Telegram message ids."""
    token, chat = secret("TELEGRAM_BOT_TOKEN"), secret("TELEGRAM_CHAT_ID")
    if not token or not chat:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in .env")
    ids = []
    for text in messages:
        resp = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                             json={"chat_id": chat, "text": text,
                                   "disable_web_page_preview": True}, timeout=30)
        resp.raise_for_status()
        ids.append(resp.json()["result"]["message_id"])
    return ids


def send_telegram_document(path: str, caption: str) -> int:
    """Send a file (the PDF report) to the configured chat. Returns the message id."""
    token, chat = secret("TELEGRAM_BOT_TOKEN"), secret("TELEGRAM_CHAT_ID")
    if not token or not chat:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in .env")
    with open(path, "rb") as fh:
        resp = requests.post(f"https://api.telegram.org/bot{token}/sendDocument",
                             data={"chat_id": chat, "caption": caption[:1000]},
                             files={"document": fh}, timeout=60)
    resp.raise_for_status()
    return resp.json()["result"]["message_id"]
