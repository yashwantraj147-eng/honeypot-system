"""
core/config_loader.py
─────────────────────
Loads config.yaml once and exposes it as a module-level dict.
Every other module imports `cfg` from here to avoid re-reading the file.
"""

import os
import yaml

_CONFIG_PATH = os.environ.get(
    "HONEYPOT_CONFIG",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml"),
)


def _load() -> dict:
    """Read and parse the YAML configuration file."""
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# Singleton config dict — imported everywhere as `from core.config_loader import cfg`
cfg = _load()
