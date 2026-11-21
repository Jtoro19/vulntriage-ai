"""Tests for the fuzzy prioritization engine (no network access needed)."""

import pytest

from fuzzy.fuzzy_engine import (
    ABLATION_RULES,
    BASE_RULES,
    EXTRA_RULES,
    build_control_system,
    coverage_check,
    prioritize,
)


@pytest.mark.parametrize("use_epss", [True, False])
def test_coverage_has_no_uncovered_combination(use_epss):
    report = coverage_check(use_epss)
    assert report["uncovered"] == []
    assert report["n_uncovered"] == 0
    assert report["combinations"] == (108 if use_epss else 36)


def test_extra_rules_are_justified_and_base_rules_kept():
    assert len(BASE_RULES) == 7
    assert all(r["justification"] for r in EXTRA_RULES)
    assert all(r["justification"] for r in ABLATION_RULES)
    assert not any("epss" in r["if"] for r in ABLATION_RULES)


def test_urgent_and_low_reference_points():
    hot = prioritize(9.8, 0.97, 9, 9)
    assert hot["label"] == "urgent"
    assert hot["priority"] > 80
    cold = prioritize(2, 0.01, 1, 1)
    assert cold["label"] == "low"
    assert cold["priority"] < 25


def test_fired_rules_structure():
    result = prioritize(9.8, 0.97, 9, 9)
    assert set(result) == {"priority", "label", "fired_rules", "inputs"}
    assert 0 <= result["priority"] <= 100
    fired = result["fired_rules"]
    assert fired and {r["id"] for r in fired} >= {"R1", "R7"}
    for r in fired:
        assert set(r) == {"id", "text", "activation"}
        assert r["text"].startswith("IF ") and " THEN priority is " in r["text"]
        assert 0.01 < r["activation"] <= 1
    acts = [r["activation"] for r in fired]
    assert acts == sorted(acts, reverse=True)
    assert result["inputs"]["cvss"] == 9.8


def test_coarse_monotonicity():
    # Centroid defuzzification is not strictly monotonic between nearby points, so only
    # compare well separated values (low vs critical CVSS, low vs high EPSS).
    for exposure, crit in [(1, 1), (5, 5), (8, 8)]:
        assert (prioritize(9.8, 0.3, exposure, crit)["priority"]
                > prioritize(2.0, 0.3, exposure, crit)["priority"])
        assert (prioritize(6.0, 0.9, exposure, crit)["priority"]
                > prioritize(6.0, 0.01, exposure, crit)["priority"])


def test_ablation_ignores_epss():
    low = prioritize(7.5, 0.0, 8, 5, use_epss=False)
    high = prioritize(7.5, 1.0, 8, 5, use_epss=False)
    assert low["priority"] == high["priority"]
    assert not any(r["id"].startswith("R") for r in low["fired_rules"])
    assert prioritize(7.5, 1.0, 8, 5)["priority"] != prioritize(7.5, 0.0, 8, 5)["priority"]


@pytest.mark.parametrize("point", [(9.8, 0.97, 9, 9), (5, 0.3, 5, 5), (7.5, 0.05, 8, 5)])
def test_matches_skfuzzy_control_system(point):
    sim = build_control_system(True)
    for name, value in zip(("cvss", "epss", "exposure", "criticality"), point, strict=True):
        sim.input[name] = value
    sim.compute()
    assert prioritize(*point)["priority"] == pytest.approx(sim.output["priority"], abs=0.05)
