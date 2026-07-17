import os
import yaml  # type: ignore
from copy import deepcopy
from typing import Any
from privesc_assistant.config.schema import validate_config

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "default_config.yaml")

def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    """Recursively merges source dictionary into target dictionary."""
    result = deepcopy(target)
    for k, v in source.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result

def load_config(user_config_path: str | None = None) -> dict[str, Any]:
    """
    Loads default configuration, merges with user configuration if provided,
    and validates the resulting configuration.
    """
    if not os.path.exists(DEFAULT_CONFIG_PATH):
        raise FileNotFoundError(f"Default config not found at {DEFAULT_CONFIG_PATH}")

    with open(DEFAULT_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f) or {}

    if user_config_path:
        if not os.path.exists(user_config_path):
            raise FileNotFoundError(f"User config not found at {user_config_path}")
            
        with open(user_config_path, "r") as f:
            user_config = yaml.safe_load(f) or {}
            
        config = _deep_merge(config, user_config)

    validate_config(config)
    return config
