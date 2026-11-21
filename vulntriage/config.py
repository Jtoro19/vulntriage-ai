"""Central configuration. Secrets come only from the environment (.env)."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
CACHE_DIR = DATA_DIR / "cache"
LAB_SCANS_DIR = DATA_DIR / "lab_scans"

# LLM provider switch: gemini (primary), groq, ollama.
LLM_PROVIDER = os.getenv("VULNTRIAGE_LLM_PROVIDER", "gemini")
GEMINI_MODEL = os.getenv("VULNTRIAGE_GEMINI_MODEL", "gemini-3.5-flash")
GROQ_MODEL = os.getenv("VULNTRIAGE_GROQ_MODEL", "openai/gpt-oss-20b")
OLLAMA_MODEL = os.getenv("VULNTRIAGE_OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
LLM_TEMPERATURE = 0.1


def secret(name: str) -> str | None:
    """Return a secret from the environment without ever logging it."""
    value = os.getenv(name)
    return value or None
