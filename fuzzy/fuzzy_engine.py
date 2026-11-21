"""Mamdani fuzzy-logic engine that prioritizes vulnerabilities (Level 3).

Inputs: CVSS (0-10), EPSS (0-1), exposure (0-10), asset criticality (0-10).
Output: priority (0-100) with the terms low, medium, high, urgent.

Design choices
- Membership functions are triangular / trapezoidal (scikit-fuzzy ``trimf`` / ``trapmf``).
- AND is min, implication is min (clipping), aggregation is max, defuzzification is the
  centroid (``skfuzzy.defuzz``). These are the same operators ``skfuzzy.control`` uses.
- Rule activation degrees are computed here (min over the antecedent memberships), so they
  are exact and citeable in a report. ``build_control_system`` builds the equivalent
  ``skfuzzy.control`` system; the tests check that both agree.
- Two rule bases: the full one (with EPSS) and the ablation one (no EPSS antecedent).
  Both are checked for coverage: every combination of input terms, evaluated at the peak
  of each term, must fire at least one rule with positive strength.
"""

from __future__ import annotations

import itertools

import numpy as np
import skfuzzy as fuzz

# ---------------------------------------------------------------- membership functions
# ("tri", (a, b, c)) or ("trap", (a, b, c, d)).  Universe: (min, max).
UNIVERSES: dict[str, tuple[float, float]] = {
    "cvss": (0.0, 10.0),
    "epss": (0.0, 1.0),
    "exposure": (0.0, 10.0),
    "criticality": (0.0, 10.0),
    "priority": (0.0, 100.0),
}

MFS: dict[str, dict[str, tuple[str, tuple[float, ...]]]] = {
    "cvss": {
        "low": ("trap", (0, 0, 2, 4)),
        "medium": ("tri", (3, 5, 7)),
        "high": ("tri", (6, 8, 9.5)),
        "critical": ("trap", (8.5, 9.5, 10, 10)),
    },
    "epss": {
        "low": ("trap", (0, 0, 0.05, 0.2)),
        "medium": ("tri", (0.1, 0.3, 0.6)),
        "high": ("trap", (0.4, 0.7, 1, 1)),
    },
    "exposure": {
        "internal": ("trap", (0, 0, 2, 4)),
        "dmz": ("tri", (2, 5, 8)),
        "internet": ("trap", (6, 8, 10, 10)),
    },
    "criticality": {
        "low": ("trap", (0, 0, 2, 4)),
        "medium": ("tri", (2, 5, 8)),
        "high": ("trap", (6, 8, 10, 10)),
    },
    "priority": {
        "low": ("trap", (0, 0, 15, 35)),
        "medium": ("tri", (20, 40, 60)),
        "high": ("tri", (45, 65, 85)),
        "urgent": ("trap", (70, 85, 100, 100)),
    },
}

INPUT_VARS = ("cvss", "epss", "exposure", "criticality")
_OUT_X = np.arange(0.0, 100.0 + 0.5, 0.5)


def _mf(var: str, term: str, x: np.ndarray) -> np.ndarray:
    kind, params = MFS[var][term]
    fn = fuzz.trimf if kind == "tri" else fuzz.trapmf
    return fn(x, np.array(params, dtype=float))


def membership(var: str, term: str, value: float) -> float:
    """Membership degree of ``value`` in ``term`` of ``var`` (value clipped to the universe)."""
    lo, hi = UNIVERSES[var]
    x = np.array([min(max(float(value), lo), hi)])
    return float(_mf(var, term, x)[0])


def term_peak(var: str, term: str) -> float:
    """Crisp value where the term has membership 1 (apex, or plateau midpoint)."""
    kind, p = MFS[var][term]
    return float(p[1]) if kind == "tri" else (p[1] + p[2]) / 2


# ---------------------------------------------------------------- rule bases
def _rule(rid: str, conds: dict[str, str], out: str, why: str | None = None) -> dict:
    cond_txt = " AND ".join(f"{v} is {t}" for v, t in conds.items())
    return {"id": rid, "if": conds, "then": out,
            "text": f"IF {cond_txt} THEN priority is {out}", "justification": why}


# The 7 rules of docs/proposal.md section 5.2, in their original meaning.
BASE_RULES: list[dict] = [
    _rule("R1", {"cvss": "critical", "epss": "high"}, "urgent"),
    _rule("R2", {"exposure": "internet", "cvss": "high"}, "high"),
    _rule("R3", {"criticality": "high", "cvss": "medium", "exposure": "internet"}, "high"),
    _rule("R4", {"exposure": "dmz", "epss": "medium"}, "medium"),
    _rule("R5", {"epss": "low", "exposure": "internal"}, "low"),
    _rule("R6", {"cvss": "low", "epss": "low"}, "low"),
    _rule("R7", {"criticality": "high", "epss": "high"}, "urgent"),
]

# Extra rules added for coverage. R8..R18 close the 4x3 (CVSS x EPSS) grid: because every
# (cvss, epss) pair has a rule, all 108 term combinations fire. R19..R22 let exposure and
# criticality modulate the result so they are not decorative.
EXTRA_RULES: list[dict] = [
    _rule("R8", {"cvss": "critical", "exposure": "internet"}, "urgent",
          "A critical flaw on an internet-facing asset is urgent even before EPSS catches up."),
    _rule("R9", {"cvss": "critical", "epss": "medium"}, "high",
          "Critical severity with moderate exploit probability stays high."),
    _rule("R10", {"cvss": "critical", "epss": "low"}, "medium",
          "Critical severity but exploitation is unlikely: still worth scheduling."),
    _rule("R11", {"cvss": "high", "epss": "high"}, "high",
          "High severity and likely exploitation (not critical, so not urgent by itself)."),
    _rule("R12", {"cvss": "high", "epss": "medium"}, "medium",
          "High severity with moderate exploit probability: medium priority."),
    _rule("R13", {"cvss": "high", "epss": "low"}, "medium",
          "High severity, unlikely exploitation: medium priority (impact still matters)."),
    _rule("R14", {"cvss": "medium", "epss": "high"}, "high",
          "EPSS signals active exploitation, which outweighs a medium base score."),
    _rule("R15", {"cvss": "medium", "epss": "medium"}, "medium",
          "Both signals moderate gives medium."),
    _rule("R16", {"cvss": "medium", "epss": "low"}, "low",
          "Medium severity and unlikely exploitation gives low."),
    _rule("R17", {"cvss": "low", "epss": "high"}, "medium",
          "Low severity but likely exploited: do not bury it, medium."),
    _rule("R18", {"cvss": "low", "epss": "medium"}, "low",
          "Low severity with moderate exploit probability stays low."),
    _rule("R19", {"exposure": "internal", "criticality": "low"}, "low",
          "Internal low-value asset: little to protect and hard to reach."),
    _rule("R20", {"criticality": "high", "cvss": "high"}, "high",
          "Severe flaw on a crown-jewel asset deserves high priority."),
    _rule("R21", {"exposure": "internal", "cvss": "medium"}, "low",
          "Medium severity that is not reachable from outside: low."),
    _rule("R22", {"criticality": "low", "exposure": "dmz", "epss": "low"}, "low",
          "Low-value asset in the DMZ with unlikely exploitation: low."),
]

# Ablation rule base (no EPSS antecedent). Adapted from the proposal rules: rules 1, 7 lose
# the EPSS term; 4, 5, 6 are replaced by CVSS x exposure equivalents. N* closes the 4x3
# (CVSS x exposure) grid, so all 36 combinations of the three remaining inputs fire.
ABLATION_RULES: list[dict] = [
    _rule("N1", {"cvss": "critical", "criticality": "high"}, "urgent",
          "Proposal rules 1 and 7 without EPSS: critical flaw on a high-value asset."),
    _rule("N2", {"exposure": "internet", "cvss": "high"}, "high",
          "Proposal rule 2, unchanged (no EPSS in it)."),
    _rule("N3", {"criticality": "high", "cvss": "medium", "exposure": "internet"}, "high",
          "Proposal rule 3, unchanged (no EPSS in it)."),
    _rule("N4", {"cvss": "critical", "exposure": "internet"}, "urgent",
          "Critical and internet-facing is urgent."),
    _rule("N5", {"cvss": "critical", "exposure": "dmz"}, "high",
          "Critical in the DMZ: high."),
    _rule("N6", {"cvss": "critical", "exposure": "internal"}, "high",
          "Critical but internal: high (impact is severe, reach is limited)."),
    _rule("N7", {"cvss": "high", "exposure": "dmz"}, "medium",
          "High severity in the DMZ: medium."),
    _rule("N8", {"cvss": "high", "exposure": "internal"}, "medium",
          "High severity, internal only: medium."),
    _rule("N9", {"cvss": "medium", "exposure": "internet"}, "medium",
          "Medium severity reachable from the internet: medium."),
    _rule("N10", {"cvss": "medium", "exposure": "dmz"}, "medium",
          "Proposal rule 4 without EPSS: medium severity in the DMZ."),
    _rule("N11", {"cvss": "medium", "exposure": "internal"}, "low",
          "Proposal rule 5 without EPSS: medium severity, internal only."),
    _rule("N12", {"cvss": "low", "exposure": "internet"}, "low",
          "Proposal rule 6 without EPSS: low severity stays low even if exposed."),
    _rule("N13", {"cvss": "low", "exposure": "dmz"}, "low",
          "Low severity in the DMZ: low."),
    _rule("N14", {"cvss": "low", "exposure": "internal"}, "low",
          "Low severity, internal: low."),
    _rule("N15", {"criticality": "high", "cvss": "high"}, "high",
          "Severe flaw on a crown-jewel asset deserves high priority."),
    _rule("N16", {"exposure": "internal", "criticality": "low"}, "low",
          "Internal low-value asset: little to protect and hard to reach."),
]

RULESETS: dict[bool, list[dict]] = {
    True: BASE_RULES + EXTRA_RULES,
    False: ABLATION_RULES,
}


def _vars_for(use_epss: bool) -> tuple[str, ...]:
    return INPUT_VARS if use_epss else tuple(v for v in INPUT_VARS if v != "epss")


# ---------------------------------------------------------------- coverage check
def coverage_check(use_epss: bool = True) -> dict:
    """Enumerate every combination of input terms and report those that fire no rule.

    Each combination is evaluated at the peak of each of its terms (membership 1). A
    combination is covered when at least one rule has activation > 0 there.
    """
    variables = _vars_for(use_epss)
    rules = RULESETS[use_epss]
    uncovered, total = [], 0
    for terms in itertools.product(*(MFS[v] for v in variables)):
        total += 1
        point = {v: term_peak(v, t) for v, t in zip(variables, terms, strict=True)}
        if not any(_activation(r, point) > 0 for r in rules):
            uncovered.append(dict(zip(variables, terms, strict=True)))
    return {"use_epss": use_epss, "combinations": total, "uncovered": uncovered,
            "n_uncovered": len(uncovered), "n_rules": len(rules)}


def _activation(rule: dict, values: dict[str, float]) -> float:
    return min(membership(v, t, values[v]) for v, t in rule["if"].items())


# ---------------------------------------------------------------- inference
_OUT_MF = {t: _mf("priority", t, _OUT_X) for t in MFS["priority"]}


def _defuzzify(activations: list[tuple[dict, float]]) -> float:
    aggregated = np.zeros_like(_OUT_X)
    for rule, act in activations:
        aggregated = np.fmax(aggregated, np.fmin(act, _OUT_MF[rule["then"]]))
    return float(fuzz.defuzz(_OUT_X, aggregated, "centroid"))


def _label(priority: float) -> str:
    """Output term with the highest membership at the crisp priority (ties go higher)."""
    degrees = {t: float(fuzz.interp_membership(_OUT_X, _OUT_MF[t], priority)) for t in _OUT_MF}
    order = list(_OUT_MF)
    return max(order, key=lambda t: (round(degrees[t], 9), order.index(t)))


def prioritize(cvss: float, epss: float, exposure: float, criticality: float,
               use_epss: bool = True) -> dict:
    """Fuzzy priority for one vulnerability.

    Returns {"priority": 0-100, "label": str, "fired_rules": [...], "inputs": {...}}.
    fired_rules holds rules with activation > 0.01, sorted by activation descending.
    With ``use_epss=False`` the EPSS-free rule base is used and ``epss`` is ignored.
    """
    values = {"cvss": float(cvss), "epss": float(epss), "exposure": float(exposure),
              "criticality": float(criticality)}
    acts = [(r, _activation(r, values)) for r in RULESETS[use_epss]]
    acts = [(r, a) for r, a in acts if a > 0]
    priority = _defuzzify(acts)
    fired = sorted(({"id": r["id"], "text": r["text"], "activation": round(a, 4)}
                    for r, a in acts if a > 0.01), key=lambda d: -d["activation"])
    return {"priority": round(priority, 2), "label": _label(priority),
            "fired_rules": fired, "inputs": {**values, "use_epss": use_epss}}


# ---------------------------------------------------------------- skfuzzy.control twin
def build_control_system(use_epss: bool = True):
    """Equivalent ``skfuzzy.control`` simulation (slower; used to cross-check the engine)."""
    from skfuzzy import control as ctrl

    antecedents = {}
    for v in _vars_for(use_epss):
        lo, hi = UNIVERSES[v]
        antecedents[v] = ctrl.Antecedent(np.linspace(lo, hi, 1001), v)
        for term in MFS[v]:
            antecedents[v][term] = _mf(v, term, antecedents[v].universe)
    out = ctrl.Consequent(_OUT_X, "priority", defuzzify_method="centroid")
    for term in MFS["priority"]:
        out[term] = _OUT_MF[term]
    rules = []
    for r in RULESETS[use_epss]:
        cond = None
        for v, t in r["if"].items():
            cond = antecedents[v][t] if cond is None else cond & antecedents[v][t]
        rules.append(ctrl.Rule(cond, out[r["then"]]))
    return ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))


if __name__ == "__main__":
    for flag in (True, False):
        rep = coverage_check(flag)
        print(f"use_epss={flag}: {rep['combinations']} combinations, "
              f"{rep['n_rules']} rules, uncovered={rep['n_uncovered']}")
    print(prioritize(9.8, 0.97, 9, 9))
