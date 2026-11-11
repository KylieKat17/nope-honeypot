# nope/config.py

import copy
from pathlib import Path

import yaml


# ================================
#   Defaults and config paths
# ================================

DEFAULTS = {
    "db_path": "nope.db",
    "listen_host": "0.0.0.0",
    "decoys": {
        "ssh": {"enabled": True, "port": 2222},
        "redis": {"enabled": True, "port": 6379},
    },
    "weights": {"connect": 1, "probe": 2, "auth": 5, "exploit": 10},
    "half_life": 300,
    "alert_threshold": 5,
    "block_threshold": 15,
    "block_seconds": 600,
    "whitelist": ["127.0.0.0/8", "::1"],
}

# Look in the current directory before falling back to the system config path
SEARCH_PATHS = [Path("config.yaml"), Path("/etc/nope/config.yaml")]


# ================================
#   Loading and merging overrides
# ================================

def merge_overrides(settings, overrides):
    for setting, override_value in overrides.items():
        # Merge nested dictionaries so unspecified settings keep their defaults
        if isinstance(override_value, dict) and isinstance(settings.get(setting), dict):
            merge_overrides(settings[setting], override_value)
        else:
            # Replace scalar and list values as a whole
            settings[setting] = override_value
    return settings


def load_config(config_path=None):
    # Copy nested defaults so merging one file cannot affect the next load
    config = copy.deepcopy(DEFAULTS)
    search_paths = [Path(config_path)] if config_path else SEARCH_PATHS
    for candidate_path in search_paths:
        if candidate_path.is_file():
            # Treat an empty YAML file as a config with no overrides
            with open(candidate_path) as config_file:
                overrides = yaml.safe_load(config_file) or {}
            return merge_overrides(config, overrides)

        # A missing explicit path is an error
        if config_path:
            raise FileNotFoundError(f"config file not found: {config_path}")
    return config
