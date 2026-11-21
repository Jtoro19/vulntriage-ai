"""Typographic normalization for generated artifacts.

LLM output often contains em/en dashes, non-breaking hyphens, curly quotes and
non-breaking spaces. The project writes plain ASCII punctuation in every artifact
(and the PDF base fonts cannot render some of those characters).
"""

from __future__ import annotations

_MAP = str.maketrans({
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": ", ",
    "\u2015": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'", "\u201c": '"',
    "\u201d": '"', "\u00a0": " ", "\u202f": " ", "\u2026": "...", "\u2022": "-",
})


def normalize(text: str) -> str:
    """Replace typographic punctuation with plain equivalents (no em dashes)."""
    return text.translate(_MAP)
