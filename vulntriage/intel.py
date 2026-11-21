"""Threat intelligence clients: NVD API 2.0, FIRST EPSS, CISA KEV and MITRE ATT&CK.

Every response is cached to disk (data/cache/) so that reruns, tests and the
evaluation notebook do not hit rate limits. NVD calls are throttled to stay
under 50 requests per 30 seconds (the limit with an API key).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from functools import lru_cache
from typing import Any

import requests

from vulntriage.cache import cached, peek
from vulntriage.config import CACHE_DIR, secret

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
USER_AGENT = "vulntriage-ai/0.1 (academic project)"


class RateLimiter:
    """Sliding-window limiter: at most `limit` calls per `window` seconds."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self.calls: deque[float] = deque()
        self.lock = threading.Lock()

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            while self.calls and now - self.calls[0] > self.window:
                self.calls.popleft()
            if len(self.calls) >= self.limit:
                time.sleep(self.window - (now - self.calls[0]) + 0.05)
            self.calls.append(time.monotonic())


# 45 instead of 50 leaves a safety margin.
_nvd_limiter = RateLimiter(45, 30.0)


def _get(url: str, params: dict | None = None, headers: dict | None = None,
         retries: int = 5, timeout: int = 60) -> requests.Response:
    """GET with exponential backoff on 403/429/5xx and network errors."""
    headers = {"User-Agent": USER_AGENT, **(headers or {})}
    delay = 2.0
    for attempt in range(retries):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code in (403, 429) or resp.status_code >= 500:
                raise requests.HTTPError(f"HTTP {resp.status_code}", response=resp)
            resp.raise_for_status()
            return resp
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError):
            if attempt == retries - 1:
                raise
            time.sleep(delay)
            delay *= 2
    raise RuntimeError("unreachable")


def _nvd_headers() -> dict:
    key = secret("NVD_API_KEY")
    return {"apiKey": key} if key else {}


# ---------------------------------------------------------------- NVD


def summarize_nvd_cve(raw: dict) -> dict:
    """Reduce an NVD CVE item to the fields the triage pipeline uses."""
    cve = raw.get("cve", raw)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score, severity, vector, attack_vector, version = None, None, None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            data = m["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            vector = data.get("vectorString")
            attack_vector = data.get("attackVector") or data.get("accessVector")
            version = data.get("version")
            break
    cwes = sorted({
        d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    return {
        "cve_id": cve.get("id"),
        "description": desc,
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cvss_version": version,
        "attack_vector": attack_vector,
        "cwes": cwes,
        "published": cve.get("published"),
        "cisa_kev_flag": bool(cve.get("cisaExploitAdd")),
    }


def nvd_cve(cve_id: str) -> dict | None:
    """Fetch one CVE from NVD (cached). Returns the summarized record or None."""
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        raise ValueError(f"invalid CVE id: {cve_id}")

    def fetch() -> dict:
        _nvd_limiter.wait()
        return _get(NVD_URL, {"cveId": cve_id}, _nvd_headers()).json()

    data = cached("nvd_cve", cve_id, fetch)
    vulns = data.get("vulnerabilities", [])
    return summarize_nvd_cve(vulns[0]) if vulns else None


def nvd_cves_for_cpe(cpe23: str, limit: int = 50) -> list[dict]:
    """CVEs affecting a CPE 2.3 match string such as cpe:2.3:a:apache:http_server:2.4.49."""

    def fetch() -> dict:
        _nvd_limiter.wait()
        params = {"virtualMatchString": cpe23, "resultsPerPage": 200}
        return _get(NVD_URL, params, _nvd_headers()).json()

    data = cached("nvd_cpe", cpe23, fetch)
    items = [summarize_nvd_cve(v) for v in data.get("vulnerabilities", [])]
    items.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)
    return items[:limit]


def nvd_search(params: dict) -> dict:
    """Raw cached NVD search (used to sample CVEs for the evaluation dataset)."""
    key = "&".join(f"{k}={v}" for k, v in sorted(params.items()))

    def fetch() -> dict:
        _nvd_limiter.wait()
        return _get(NVD_URL, params, _nvd_headers(), timeout=120).json()

    return cached("nvd_search", key, fetch)


def cpe22_to_23(cpe: str) -> str | None:
    """Convert an Nmap CPE 2.2 URI (cpe:/a:vendor:product:version) to a CPE 2.3 string."""
    if not cpe.startswith("cpe:/"):
        return cpe if cpe.startswith("cpe:2.3:") else None
    parts = cpe[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None  # without a version the match would be far too broad
    parts = (parts + ["*"] * 11)[:11]
    return "cpe:2.3:" + ":".join(p or "*" for p in parts)


# ---------------------------------------------------------------- EPSS


def epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """EPSS probability and percentile for each CVE (cached per CVE, batched by 100)."""
    out: dict[str, dict] = {}
    missing = []
    for cve in {c.upper() for c in cve_ids}:
        path_hit = peek("epss", cve)
        if path_hit is not None:
            out[cve] = path_hit
        else:
            missing.append(cve)
    for i in range(0, len(missing), 100):
        batch = missing[i:i + 100]
        data = _get(EPSS_URL, {"cve": ",".join(batch)}).json().get("data", [])
        found = {d["cve"]: {"epss": float(d["epss"]), "percentile": float(d["percentile"]),
                            "date": d.get("date")} for d in data}
        for cve in batch:
            value = found.get(cve, {"epss": 0.0, "percentile": 0.0, "date": None})
            cached("epss", cve, lambda v=value: v)
            out[cve] = value
    return out


def epss_score(cve_id: str) -> dict:
    return epss_scores([cve_id])[cve_id.upper()]


# ---------------------------------------------------------------- CISA KEV


@lru_cache(maxsize=1)
def kev_catalog() -> dict[str, dict]:
    """CISA KEV catalog indexed by CVE id (downloaded once and cached)."""
    data = cached("kev", "catalog", lambda: _get(KEV_URL).json())
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def kev_entry(cve_id: str) -> dict | None:
    entry = kev_catalog().get(cve_id.upper())
    if not entry:
        return None
    return {k: entry.get(k) for k in (
        "cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
        "knownRansomwareCampaignUse", "requiredAction")}


# ---------------------------------------------------------------- MITRE ATT&CK


@lru_cache(maxsize=1)
def attack_techniques() -> list[dict]:
    """Enterprise ATT&CK techniques (id, name, tactics, description) from the STIX bundle."""
    path = CACHE_DIR / "attack" / "techniques.json"
    if path.exists():
        return json.loads(path.read_text())
    bundle = _get(ATTACK_URL, timeout=300).json()
    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        techniques.append({
            "id": ext["external_id"],
            "name": obj["name"],
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "description": obj.get("description", ""),
            "url": ext.get("url"),
        })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(techniques))
    return techniques


# Curated bridge from common weakness classes to the ATT&CK technique an
# attacker would use to exploit them. ATT&CK has no official CWE mapping, so
# this table is expert judgment and is documented as such in the README.
CWE_TO_ATTACK: dict[str, str] = {
    "CWE-78": "T1059", "CWE-77": "T1059", "CWE-94": "T1059", "CWE-95": "T1059",
    "CWE-917": "T1059", "CWE-1336": "T1059", "CWE-502": "T1190", "CWE-89": "T1190",
    "CWE-22": "T1083", "CWE-23": "T1083", "CWE-434": "T1505.003", "CWE-287": "T1078",
    "CWE-306": "T1190", "CWE-798": "T1078.001", "CWE-521": "T1110", "CWE-307": "T1110",
    "CWE-79": "T1189", "CWE-352": "T1185", "CWE-918": "T1090", "CWE-611": "T1190",
    "CWE-200": "T1005", "CWE-269": "T1068", "CWE-276": "T1222", "CWE-119": "T1203",
    "CWE-787": "T1203", "CWE-416": "T1203", "CWE-120": "T1203", "CWE-20": "T1190",
    "CWE-400": "T1499", "CWE-770": "T1499", "CWE-863": "T1068", "CWE-284": "T1190",
}

_WORD = re.compile(r"[a-z0-9]+")


def search_attack(query: str, k: int = 3) -> list[dict]:
    """Keyword search over ATT&CK techniques. A CWE id in the query uses the bridge table."""
    techniques = attack_techniques()
    by_id = {t["id"]: t for t in techniques}
    results: list[dict] = []
    for cwe in re.findall(r"CWE-\d+", query.upper()):
        tid = CWE_TO_ATTACK.get(cwe)
        if tid and tid in by_id and by_id[tid] not in results:
            results.append(by_id[tid])
    terms = set(_WORD.findall(query.lower())) - {"the", "a", "of", "and", "in", "to", "cwe"}
    scored = []
    for t in techniques:
        name_terms = set(_WORD.findall(t["name"].lower()))
        desc_terms = set(_WORD.findall(t["description"][:600].lower()))
        score = 3 * len(terms & name_terms) + len(terms & desc_terms)
        if score:
            scored.append((score, t))
    scored.sort(key=lambda x: -x[0])
    for _, t in scored:
        if len(results) >= k:
            break
        if t not in results:
            results.append(t)
    return [{"id": t["id"], "name": t["name"], "tactics": t["tactics"], "url": t["url"]}
            for t in results[:k]]


def enrich_cve(cve_id: str) -> dict[str, Any]:
    """NVD + EPSS + KEV + ATT&CK for one CVE: the record every component consumes."""
    record = nvd_cve(cve_id) or {"cve_id": cve_id.upper(), "cvss_score": None, "cwes": []}
    record["epss"] = epss_score(cve_id)["epss"]
    kev = kev_entry(cve_id)
    record["in_kev"] = kev is not None
    record["kev"] = kev
    query = " ".join(record.get("cwes", [])) + " " + record.get("description", "")[:200]
    record["attack"] = search_attack(query, k=1)
    return record
