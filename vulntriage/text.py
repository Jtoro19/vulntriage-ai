"""Typographic normalization for generated artifacts.

LLM output often contains em/en dashes, non-breaking hyphens, curly quotes and
non-breaking spaces. The project writes plain ASCII punctuation in every artifact
(and the PDF base fonts cannot render some of those characters).
"""

from __future__ import annotations

_MAP = str.maketrans({
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": ", ",
    "―": "-", "−": "-", "‘": "'", "’": "'", "“": '"',
    "”": '"', " ": " ", " ": " ", "…": "...", "•": "-",
})


def normalize(text: str) -> str:
    """Replace typographic punctuation with plain equivalents (no em dashes)."""
    return text.translate(_MAP)
