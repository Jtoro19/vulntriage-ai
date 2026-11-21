"""Tiny JSON disk cache so reruns and evaluations never hit API rate limits."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vulntriage.config import CACHE_DIR


def _path(namespace: str, key: str) -> Path:
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)[:60]
    return CACHE_DIR / namespace / f"{safe}_{digest}.json"


def cached(namespace: str, key: str, fetch: Callable[[], Any]) -> Any:
    """Return the cached value for key, calling fetch() and storing it on a miss."""
    path = _path(namespace, key)
    if path.exists():
        return json.loads(path.read_text())
    value = fetch()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return value


def peek(namespace: str, key: str) -> Any | None:
    """Return the cached value or None without fetching."""
    path = _path(namespace, key)
    return json.loads(path.read_text()) if path.exists() else None
