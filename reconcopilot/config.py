"""Configuration management for ReconCopilot.

Loads settings from ~/.config/reconcopilot/config.yaml (or ~/.config/ReconCopilot/config.yaml),
falling back to a bundled default configuration. Environment variables can override
any configuration value (e.g., ANTHROPIC_API_KEY overrides ai.api_key).
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "ReconCopilot",
        "environment": "development",
        "log_level": "INFO",
    },
    "ai": {
        "provider": "anthropic",
        "api_key": "",
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 4096,
        "temperature": 0.2,
    },
    "database": {
        "path": "~/.config/reconcopilot/reconcopilot.db",
        "timeout": 30.0,
    },
    "audit": {
        "log_file": "~/.config/reconcopilot/audit.log",
        "enabled": True,
        "format": "json",
    },
    "scope": {
        "allowlist_file": "",
        "strict_mode": True,
        "allow_private_ips": False,
    },
    "recon": {
        "passive_only": True,
        "threads": 10,
        "timeout_seconds": 30,
        "rate_limit": 5,
    },
    "triage": {
        "severity_threshold": 4.0,
        "auto_suggest_remediation": True,
    },
    "tracking": {
        "check_interval_hours": 24,
        "notify_on_changes": True,
    },
    "report": {
        "output_dir": "./output/reports",
        "default_format": "markdown",
    },
}

# Explicit aliases for environment variable overrides
ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "ANTHROPIC_API_KEY": ("ai", "api_key"),
    "ANTHROPIC_MODEL": ("ai", "model"),
    "RECONCOPILOT_DB_PATH": ("database", "path"),
    "DATABASE_PATH": ("database", "path"),
    "RECONCOPILOT_AUDIT_LOG": ("audit", "log_file"),
    "AUDIT_LOG_FILE": ("audit", "log_file"),
    "RECONCOPILOT_LOG_LEVEL": ("app", "log_level"),
    "RECONCOPILOT_SCOPE_FILE": ("scope", "allowlist_file"),
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merges override dictionary into base dictionary."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _cast_env_value(original_val: Any, str_val: str) -> Any:
    """Casts environment variable string to the matching type of original_val."""
    if isinstance(original_val, bool):
        return str_val.lower() in ("true", "1", "yes", "on")
    if isinstance(original_val, int):
        try:
            return int(str_val)
        except ValueError:
            return str_val
    if isinstance(original_val, float):
        try:
            return float(str_val)
        except ValueError:
            return str_val
    return str_val


def _apply_nested_env_override(
    data: dict[str, Any], keys: tuple[str, ...], value: str
) -> None:
    """Sets a nested dictionary key from a tuple of string path segments."""
    curr = data
    for key in keys[:-1]:
        if key not in curr or not isinstance(curr[key], dict):
            curr[key] = {}
        curr = curr[key]
    leaf_key = keys[-1]
    curr[leaf_key] = _cast_env_value(curr.get(leaf_key), value)


def _apply_env_overrides(config_dict: dict[str, Any]) -> dict[str, Any]:
    """Applies environment variable overrides to configuration."""
    merged = copy.deepcopy(config_dict)

    # 1. Apply explicit environment aliases
    for env_var, path_keys in ENV_ALIASES.items():
        val = os.getenv(env_var)
        if val is not None and val != "":
            _apply_nested_env_override(merged, path_keys, val)

    # 2. Generic prefix overrides:
    # RECONCOPILOT__AI__API_KEY or RECONCOPILOT_AI_API_KEY
    for env_key, env_val in os.environ.items():
        if not env_key.startswith("RECONCOPILOT_"):
            continue

        raw = env_key[len("RECONCOPILOT_") :]
        if not raw:
            continue

        # Check double underscore separator first
        if "__" in raw:
            parts = tuple(p.lower() for p in raw.split("__"))
            _apply_nested_env_override(merged, parts, env_val)
            continue

        # Match single underscore if top-level section matches
        parts_candidates = raw.lower().split("_")
        if len(parts_candidates) >= 2:
            section = parts_candidates[0]
            field = "_".join(parts_candidates[1:])
            if section in merged and isinstance(merged[section], dict):
                _apply_nested_env_override(merged, (section, field), env_val)

    return merged


class ConfigDict(dict):
    """Dictionary subclass supporting attribute-style dot access."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        for key, value in list(self.items()):
            if isinstance(value, dict) and not isinstance(value, ConfigDict):
                self[key] = ConfigDict(value)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'ConfigDict' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def __delattr__(self, name: str) -> None:
        try:
            del self[name]
        except KeyError:
            raise AttributeError(f"'ConfigDict' object has no attribute '{name}'")

    def to_dict(self) -> dict[str, Any]:
        """Convert back to a standard Python dictionary."""
        res: dict[str, Any] = {}
        for k, v in self.items():
            if isinstance(v, ConfigDict):
                res[k] = v.to_dict()
            else:
                res[k] = v
        return res


def get_default_config_search_paths() -> list[Path]:
    """Returns candidate paths for config.yaml."""
    home = Path.home()
    return [
        home / ".config" / "reconcopilot" / "config.yaml",
        home / ".config" / "ReconCopilot" / "config.yaml",
    ]


def load_config(config_path: str | Path | None = None) -> ConfigDict:
    """Loads configuration from file, default bundle, and environment variables.

    Args:
        config_path: Optional explicit path to configuration YAML file.

    Returns:
        ConfigDict object containing resolved settings.
    """
    config_data = copy.deepcopy(DEFAULT_CONFIG)
    file_to_load: Path | None = None

    if config_path is not None:
        p = Path(config_path).expanduser().resolve()
        if p.is_file():
            file_to_load = p
    elif os.getenv("RECONCOPILOT_CONFIG"):
        p = Path(os.environ["RECONCOPILOT_CONFIG"]).expanduser().resolve()
        if p.is_file():
            file_to_load = p
    else:
        for candidate in get_default_config_search_paths():
            if candidate.is_file():
                file_to_load = candidate
                break

    if file_to_load is not None:
        try:
            with open(file_to_load, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config_data = _deep_merge(config_data, loaded)
        except Exception as exc:
            # Fall back to defaults if parsing fails, but log/raise warning
            import sys

            print(
                f"Warning: Failed to parse config file at {file_to_load}: {exc}",
                file=sys.stderr,
            )

    # Apply environment variable overrides
    final_dict = _apply_env_overrides(config_data)
    return ConfigDict(final_dict)
