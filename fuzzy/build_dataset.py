"""Build data/eval/cves.csv, the evaluation dataset for the fuzzy prioritizer.

Sources
- lab: every CVE NVD links (CPE 2.3 virtual match) to the products of the Docker lab.
- nvd_sample: a reproducible sample of NVD (fixed publication windows, fixed seed).

Documented assumptions (also in fuzzy/README.md)
- exposure is derived from the CVSS attack vector: NETWORK 8, ADJACENT 5, LOCAL 2,
  PHYSICAL 1 (unknown vectors get 5). It is a proxy for "how reachable is the flaw".
- criticality: lab assets use the table below; sample CVEs are fixed at 5 (medium) because
  there is no asset behind them.
- CVEs without a CVSS score are dropped and the count is printed.
- The KEV flag is NOT balanced: the dataset keeps whatever base rate it has.

Run: uv run python -m fuzzy.build_dataset
"""

from __future__ import annotations

import csv
import random

from vulntriage.config import DATA_DIR
from vulntriage.intel import epss_scores, kev_catalog, nvd_cves_for_cpe, nvd_search

OUT = DATA_DIR / "eval" / "cves.csv"
SEED = 42

# CPE 2.3 string -> (asset, criticality 0-10). Criticality is an analyst judgment for the lab:
# CI servers hold secrets (9), the app server and CMS hold business logic or data (7-9),
# a plain web front is 7, training apps (DVWA, Juice Shop) are 3.
LAB_ASSETS: dict[str, tuple[str, int]] = {
    "cpe:2.3:a:apache:http_server:2.4.49": ("httpd 2.4.49", 7),
    "cpe:2.3:a:apache:tomcat:8.5.19": ("Tomcat 8.5.19", 7),
    "cpe:2.3:a:drupal:drupal:8.5.0": ("Drupal 8.5.0", 8),
    "cpe:2.3:a:oracle:weblogic_server:10.3.6.0": ("WebLogic 10.3.6.0", 9),
    "cpe:2.3:a:jenkins:jenkins:2.46.1": ("Jenkins 2.46.1", 9),
    "cpe:2.3:a:elastic:elasticsearch:1.4.2": ("Elasticsearch 1.4.2", 8),
    "cpe:2.3:a:dvwa_project:dvwa:1.9": ("DVWA", 3),
    "cpe:2.3:a:owasp:juice_shop:*": ("Juice Shop", 3),
}

EXPOSURE_BY_VECTOR = {"NETWORK": 8, "ADJACENT": 5, "LOCAL": 2, "PHYSICAL": 1}
SAMPLE_CRITICALITY = 5
# One window per year, Jan 1 to Apr 28 (NVD caps a window at 120 days).
SAMPLE_YEARS = range(2016, 2026)
PER_WINDOW = 10

FIELDS = ["cve_id", "source", "cvss", "attack_vector", "epss", "in_kev", "exposure",
          "criticality", "cwes", "asset"]


def exposure_from_vector(vector: str | None) -> int:
    if not vector:
        return 5
    return next((v for k, v in EXPOSURE_BY_VECTOR.items() if vector.upper().startswith(k)), 5)


def lab_cves() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for cpe, (asset, crit) in LAB_ASSETS.items():
        for rec in nvd_cves_for_cpe(cpe, limit=1000):
            cur = found.get(rec["cve_id"])
            if cur is None:
                found[rec["cve_id"]] = {**rec, "criticality": crit, "asset": asset}
            elif crit > cur["criticality"]:  # CVE shared by several assets: keep the most critical
                cur.update(criticality=crit, asset=asset)
    return found


def sample_cves(exclude: set[str]) -> dict[str, dict]:
    """Seeded sample: one random page of PER_WINDOW CVEs inside a fixed window per year."""
    from vulntriage.intel import summarize_nvd_cve

    rng = random.Random(SEED)
    out: dict[str, dict] = {}
    for year in SAMPLE_YEARS:
        base = {"pubStartDate": f"{year}-01-01T00:00:00.000",
                "pubEndDate": f"{year}-04-28T23:59:59.999"}
        total = nvd_search({**base, "resultsPerPage": 1}).get("totalResults", 0)
        if total < PER_WINDOW:
            continue
        start = rng.randrange(0, total - PER_WINDOW + 1)
        page = nvd_search({**base, "resultsPerPage": PER_WINDOW, "startIndex": start})
        for item in page.get("vulnerabilities", []):
            rec = summarize_nvd_cve(item)
            if rec["cve_id"] not in exclude:
                out[rec["cve_id"]] = {**rec, "criticality": SAMPLE_CRITICALITY, "asset": ""}
    return out


def main() -> None:
    lab = lab_cves()
    sample = sample_cves(set(lab))
    rows_in = [(c, "lab", r) for c, r in lab.items()] + [(c, "nvd_sample", r)
                                                          for c, r in sample.items()]
    dropped = [c for c, _, r in rows_in if r["cvss_score"] is None]
    rows_in = [t for t in rows_in if t[2]["cvss_score"] is not None]

    epss = epss_scores([c for c, _, _ in rows_in])
    kev = kev_catalog()
    rows = []
    for cve_id, source, r in sorted(rows_in, key=lambda t: t[0]):
        rows.append({
            "cve_id": cve_id, "source": source, "cvss": r["cvss_score"],
            "attack_vector": r["attack_vector"] or "", "epss": epss[cve_id]["epss"],
            "in_kev": int(cve_id in kev), "exposure": exposure_from_vector(r["attack_vector"]),
            "criticality": r["criticality"], "cwes": ";".join(r["cwes"]), "asset": r["asset"],
        })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    n_kev = sum(r["in_kev"] for r in rows)
    print(f"wrote {OUT}: {len(rows)} CVEs "
          f"(lab {sum(r['source'] == 'lab' for r in rows)}, "
          f"nvd_sample {sum(r['source'] == 'nvd_sample' for r in rows)})")
    print(f"dropped without CVSS: {len(dropped)}")
    print(f"KEV base rate: {n_kev}/{len(rows)} = {n_kev / len(rows):.1%}")
    for src in ("lab", "nvd_sample"):
        sub = [r for r in rows if r["source"] == src]
        k = sum(r["in_kev"] for r in sub)
        print(f"  {src}: {k}/{len(sub)} in KEV")


if __name__ == "__main__":
    main()
