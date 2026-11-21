"""Lab asset inventory (lab/assets.yaml): simulated role, exposure and criticality per host."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

from vulntriage.config import ROOT

ASSETS_PATH = ROOT / "lab" / "assets.yaml"
DEFAULT = {"name": "Unknown lab asset", "zone": "internal", "exposure": 2.0, "criticality": 5.0}


@lru_cache(maxsize=1)
def load_assets(path: Path = ASSETS_PATH) -> dict:
    """Return {"scenario": str, "zones": {...}, "assets": {"lab-host-N": {...}}}."""
    data = yaml.safe_load(path.read_text())
    zones = data["zones"]
    for asset in data["assets"].values():
        asset["exposure"] = float(zones[asset["zone"]])
        asset["criticality"] = float(asset["criticality"])
    return data


def asset_for(host: str | None) -> dict:
    """Asset record for an anonymized host (lab-host-N) or lab IP (172.30.0.N)."""
    m = re.search(r"(?:lab-host-|172\.30\.0\.)(\d+)$", str(host or ""))
    if not m:
        return dict(DEFAULT)
    return {**DEFAULT, **load_assets()["assets"].get(f"lab-host-{m.group(1)}", {})}


def scenario() -> str:
    return load_assets()["scenario"]
