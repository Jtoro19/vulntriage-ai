"""Evaluate the fuzzy prioritizer against a CVSS baseline and an EPSS-free ablation.

Ground truth (proxy): membership in the CISA KEV catalog (exploited in the wild).

Metric definitions (k is the cutoff in the ranking, P = number of KEV CVEs in the dataset)
- Precision@10 = KEV hits in the top 10 / 10
- Recall@20    = KEV hits in the top 20 / P
- F1@20        = harmonic mean of Precision@20 and Recall@20 (same cutoff for both)
Ties: every method sorts by score descending and breaks ties by cve_id ascending, so the
ranking is deterministic. CVSS has many ties (scores like 9.8), so the tie rule matters for
the baseline; the rule is arbitrary with respect to exploitability, it favors no method.

Latency: mean wall time (ms) of scoring one CVE, over REPS passes through the dataset
(time.perf_counter). For the baseline this is just reading the CVSS score.

Run: uv run python -m fuzzy.evaluate
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from fuzzy.fuzzy_engine import prioritize  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "eval" / "cves.csv"
RESULTS = ROOT / "fuzzy" / "results"
FIGURES = ROOT / "docs" / "figures"
REPS = 5
METHODS = ("cvss", "fuzzy", "fuzzy_no_epss")
LABELS = {"cvss": "CVSS baseline", "fuzzy": "Fuzzy (with EPSS)", "fuzzy_no_epss": "Fuzzy (no EPSS)"}
PALETTE = {"cvss": "#4C78A8", "fuzzy": "#F58518", "fuzzy_no_epss": "#54A24B"}
SOURCE = "Source: NVD (CVSS), FIRST EPSS, CISA KEV; n={n} CVEs, {p} in KEV"

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                     "axes.spines.right": False})


def scorers() -> dict:
    return {
        "cvss": lambda r: r.cvss,
        "fuzzy": lambda r: prioritize(r.cvss, r.epss, r.exposure, r.criticality)["priority"],
        "fuzzy_no_epss": lambda r: prioritize(r.cvss, r.epss, r.exposure, r.criticality,
                                              use_epss=False)["priority"],
    }


def rank(df: pd.DataFrame, score_col: str) -> pd.DataFrame:
    return df.sort_values([score_col, "cve_id"], ascending=[False, True]).reset_index(drop=True)


def metrics_at(ranked: pd.DataFrame, positives: int) -> dict:
    hits10 = int(ranked["in_kev"].head(10).sum())
    hits20 = int(ranked["in_kev"].head(20).sum())
    p10, p20, r20 = hits10 / 10, hits20 / 20, hits20 / positives
    f1 = 2 * p20 * r20 / (p20 + r20) if (p20 + r20) else 0.0
    return {"precision_at_10": p10, "recall_at_20": r20, "f1_at_20": f1,
            "precision_at_20": p20, "hits_top10": hits10, "hits_top20": hits20}


def expected_hits(df: pd.DataFrame, score_col: str, k: int) -> float:
    """Exact expected KEV hits in the top k under uniformly random tie-breaking.

    Groups strictly above the cutoff score count fully; the tied group straddling the
    cutoff fills the remaining m slots at random, so its expected hits are m * h / g
    (hypergeometric mean, g = group size, h = KEV CVEs in the group).
    """
    ordered = df.sort_values(score_col, ascending=False)
    cutoff = ordered[score_col].iloc[k - 1]
    above = ordered[ordered[score_col] > cutoff]["in_kev"].sum()
    tied = ordered[ordered[score_col] == cutoff]
    return float(above + (k - len(ordered[ordered[score_col] > cutoff])) * tied["in_kev"].mean())


def expected_metrics(df: pd.DataFrame, score_col: str, positives: int) -> dict:
    h10, h20 = expected_hits(df, score_col, 10), expected_hits(df, score_col, 20)
    # F1@20 = 2PR/(P+R) = 2*hits/(20+positives) is linear in hits, so its expectation is exact.
    return {"precision_at_10": h10 / 10, "recall_at_20": h20 / positives,
            "f1_at_20": 2 * h20 / (20 + positives)}


def mean_latency_ms(fn, rows) -> float:
    start = time.perf_counter()
    for _ in range(REPS):
        for r in rows:
            fn(r)
    return (time.perf_counter() - start) / (REPS * len(rows)) * 1000


def decision_surface(path: Path, exposure: float = 8, criticality: float = 5) -> None:
    cvss = np.linspace(0, 10, 41)
    epss = np.linspace(0, 1, 41)
    grid = np.array([[prioritize(c, e, exposure, criticality)["priority"] for e in epss]
                     for c in cvss])
    fig, ax = plt.subplots(figsize=(7.5, 6))
    im = ax.imshow(grid, origin="lower", aspect="auto", cmap="viridis", vmin=0, vmax=100,
                   extent=(0, 1, 0, 10))
    fig.colorbar(im, ax=ax, label="Fuzzy priority (0-100)")
    ax.set_xlabel("EPSS (probability of exploitation, 0-1)")
    ax.set_ylabel("CVSS base score (0-10)")
    ax.set_title(f"Fuzzy decision surface (exposure = {exposure:g}, criticality = {criticality:g})")
    fig.text(0.01, 0.01, "Exposure 8 = internet-facing; criticality 5 = medium asset. "
             "Mamdani, centroid defuzzification.", fontsize=8, color="#555")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(path, dpi=150)
    plt.close(fig)


def metrics_chart(path: Path, metrics: dict, n: int, p: int) -> None:
    names = [("precision_at_10", "Precision@10"), ("recall_at_20", "Recall@20"),
             ("f1_at_20", "F1@20")]
    x = np.arange(len(names))
    width = 0.26
    fig, ax = plt.subplots(figsize=(8.5, 5.5))
    for i, m in enumerate(METHODS):
        vals = [metrics[m]["expected_random_ties"][k] for k, _ in names]
        det = [metrics[m][k] for k, _ in names]
        bars = ax.bar(x + (i - 1) * width, vals, width, label=LABELS[m], color=PALETTE[m])
        ax.bar_label(bars, fmt="%.2f", fontsize=9, padding=2)
        ax.scatter(x + (i - 1) * width, det, marker="D", s=28, color="black", zorder=3,
                   label="Deterministic (cve_id tie-break)" if i == 0 else None)
    ax.set_xticks(x, [label for _, label in names])
    ax.set_ylabel("Score (0-1)")
    ax.set_ylim(0, 1.05)
    ax.set_title("Ranking quality against CISA KEV (higher is better)\n"
                 "Bars: expected value under random tie-breaking; diamonds: cve_id tie-break")
    ax.legend(frameon=False)
    fig.text(0.01, 0.01, SOURCE.format(n=n, p=p) + ". Ties broken by CVE id.",
             fontsize=8, color="#555")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main() -> None:
    df = pd.read_csv(DATA)
    n, positives = len(df), int(df["in_kev"].sum())
    rows = list(df.itertuples(index=False))
    fns = scorers()
    for m in METHODS:
        df[f"score_{m}"] = [fns[m](r) for r in rows]

    metrics: dict = {}
    rankings = []
    for m in METHODS:
        ranked = rank(df, f"score_{m}")
        metrics[m] = metrics_at(ranked, positives)
        metrics[m]["expected_random_ties"] = expected_metrics(df, f"score_{m}", positives)
        metrics[m]["distinct_scores"] = int(df[f"score_{m}"].nunique())
        metrics[m]["latency_ms"] = mean_latency_ms(fns[m], rows)
        top = ranked.head(n)[["cve_id", "in_kev", f"score_{m}"]].copy()
        top.columns = ["cve_id", "in_kev", "score"]
        top.insert(0, "rank", range(1, n + 1))
        top.insert(0, "method", m)
        rankings.append(top)

    RESULTS.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    out = {"dataset": {"n": n, "kev_positives": positives, "kev_base_rate": positives / n,
                       "latency_reps": REPS},
           "definitions": {"precision_at_10": "KEV hits in top 10 / 10",
                           "recall_at_20": "KEV hits in top 20 / KEV positives",
                           "f1_at_20": "harmonic mean of precision@20 and recall@20",
                           "ties": "deterministic numbers: score descending, then cve_id ascending",
                           "expected_random_ties": "exact expectation under uniformly random "
                           "tie-breaking (hypergeometric mean within the tied group "
                           "straddling the cutoff; F1@20 = 2*hits/(20+positives) is linear "
                           "in hits)"},
           "methods": metrics}
    (RESULTS / "metrics.json").write_text(json.dumps(out, indent=2))
    pd.concat(rankings).to_csv(RESULTS / "rankings.csv", index=False)
    metrics_chart(FIGURES / "metrics_comparison.png", metrics, n, positives)
    decision_surface(FIGURES / "decision_surface.png")

    print(f"n={n} KEV={positives} ({positives / n:.1%})")
    for m in METHODS:
        v = metrics[m]
        print(f"{LABELS[m]:20s} P@10={v['precision_at_10']:.2f} R@20={v['recall_at_20']:.2f} "
              f"F1@20={v['f1_at_20']:.2f} hits10={v['hits_top10']} hits20={v['hits_top20']} "
              f"distinct={v['distinct_scores']} latency={v['latency_ms']:.4f} ms")
        e = v["expected_random_ties"]
        print(f"  expected (random ties): P@10={e['precision_at_10']:.3f} "
              f"R@20={e['recall_at_20']:.3f} F1@20={e['f1_at_20']:.3f}")


if __name__ == "__main__":
    main()
