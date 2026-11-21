# Level 3: fuzzy-logic prioritization

Mamdani fuzzy system (scikit-fuzzy primitives) that turns CVSS, EPSS, exposure and asset
criticality into a 0-100 priority (low, medium, high, urgent) with the rules that fired.

## Design

- Inputs: CVSS 0-10 (low, medium, high, critical), EPSS 0-1 (low, medium, high), exposure 0-10
  (internal, dmz, internet), criticality 0-10 (low, medium, high). Output: priority 0-100.
- Triangular and trapezoidal membership functions, min for AND, max aggregation, centroid
  defuzzification. Rule activations are computed explicitly (min over antecedents), so they
  are exact; the tests cross-check the result against `skfuzzy.control`.
- Rules: the 7 proposal rules plus 15 added rules, each with a one-line justification in
  `fuzzy_engine.py` (`EXTRA_RULES`). `coverage_check()` enumerates all 4x3x3x3 = 108 term
  combinations (at each term peak) and reports 0 uncovered. The ablation (`use_epss=False`)
  has its own 16-rule base over the 36 remaining combinations, also 0 uncovered.
- API: `prioritize(cvss, epss, exposure, criticality, use_epss=True)` returns
  `{"priority", "label", "fired_rules": [{"id", "text", "activation"}], "inputs"}`.

## Reproduce

```bash
uv run python -m fuzzy.build_dataset     # data/eval/cves.csv (cached NVD/EPSS/KEV calls)
uv run python -m fuzzy.evaluate          # fuzzy/results/*, docs/figures/*.png
uv run jupyter nbconvert --to notebook --execute --inplace fuzzy/evaluation.ipynb
uv run pytest tests/test_fuzzy.py -q && uv run ruff check fuzzy tests/test_fuzzy.py
```

## Dataset

510 CVEs: 410 linked by NVD to the lab products (httpd 2.4.49, Tomcat 8.5.19, Drupal 8.5.0,
WebLogic 10.3.6.0, Jenkins 2.46.1, Elasticsearch 1.4.2; DVWA and Juice Shop have no NVD CPE
matches) and 100 sampled from NVD (10 per year, 2016-2025, seed 42). No CVE lacked a CVSS
score. KEV base rate: 15/510 = 2.9% (all 15 are lab CVEs; the sample has none). Exposure is
derived from the CVSS attack vector (NETWORK 8, ADJACENT 5, LOCAL 2, PHYSICAL 1); criticality
comes from a table for lab assets and is 5 for sample CVEs. The dataset is larger than the
~200 in the proposal because all 410 lab-linked CVEs were kept (they alone exceed 200).

## Results (ground truth: CISA KEV; `fuzzy/results/metrics.json`)

Precision@10 = KEV hits in top 10 / 10. Recall@20 = hits in top 20 / 15. F1@20 = harmonic mean
of Precision@20 and Recall@20. Ties are broken by cve_id ascending.

Deterministic numbers (cve_id tie-break) and expected numbers under uniformly random
tie-breaking (exact, hypergeometric mean within the tied group that straddles the cutoff;
F1@20 = 2*hits/(20+15) is linear in hits, so its expectation is exact). The bar chart shows
the expected values as bars and the deterministic ones as diamonds.

| Method | P@10 det. | P@10 exp. | R@20 det. | R@20 exp. | F1@20 det. | F1@20 exp. | Latency (ms/CVE) |
|---|---|---|---|---|---|---|---|
| CVSS baseline | 0.50 | 0.204 | 0.40 | 0.272 | 0.34 | 0.233 | 0.00002 |
| Fuzzy (with EPSS) | 0.80 | 0.833 | 0.80 | 0.800 | 0.69 | 0.686 | 0.68 |
| Fuzzy (no EPSS) | 0.50 | 0.204 | 0.40 | 0.272 | 0.34 | 0.233 | 0.54 |

The baseline's deterministic numbers are luckier than its expectation; the fuzzy ones are
stable under tie-breaking.

## Limitations (details in the notebook)

- The gain comes entirely from EPSS (the ablation equals the baseline), and EPSS is correlated
  with KEV, so the comparison is biased in favor of any method that uses EPSS.
- Only 15 positives: the metrics are coarse and no significance is claimed. 12 CVEs tie at the
  top fuzzy score (88.33), so the tie-break influences Precision@10 (hence the expected-value columns).
- Exposure is nearly constant (485/510 are NETWORK) and criticality is hand-assigned and
  confounded with the lab source; membership functions are expert judgment.
- One added rule was removed after a first run showed a non-monotonic region (Recall@20 moved
  from 0.73 to 0.80): this is tuning on the evaluation set. Centroid defuzzification is not
  strictly monotonic, so tests assert only coarse monotonicity.
