#!/usr/bin/env python3
"""
XDR Unified Configuration Loader.

Loads configuration from xdr_config.yaml with:
  - Environment variable overrides (XDR_<SECTION>_<KEY>)
  - Default values fallback (if YAML file is missing)
  - Type validation and coercion

Usage:
    from config_loader import get_config
    cfg = get_config()
    print(cfg["engine"]["nic_interface"])
    print(cfg["correlation"]["window_secs"])
"""

import os
import logging
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger("xdr.config")

# ── Config file locations ────────────────────────────────

CONFIG_PATHS = [
    Path("/opt/xdr/xdr-core/xdr_config.yaml"),
    Path(__file__).parent / "xdr_config.yaml",
    Path.home() / ".xdr_config.yaml",
]

# ── Default configuration ────────────────────────────────

DEFAULTS: dict[str, dict[str, Any]] = {
    "engine": {
        "nic_interface": "auto",
        "dashboard_port": 29992,
        "xdr_dir": "/opt/xdr",
    },
    "cache": {
        "conn_cache_max": 500000,
        "conn_cache_ttl": 600,
        "proc_cache_max": 1500000,
        "proc_cache_ttl": 1800,
        "event_history_max": 5000,
    },
    "correlation": {
        "window_secs": 60,
        "exec_rate_threshold": 50,
        "connect_rate_threshold": 100,
        "beacon_detect_count": 10,
    },
    "dns": {
        "dga_entropy_threshold": 3.8,
        "dga_consonant_ratio": 0.7,
        "dga_min_length": 12,
        "tunnel_txt_threshold": 10,
        "tunnel_subdomain_len": 40,
    },
    "integrity": {
        "scan_interval_seconds": 3600,
    },
    "threat_intel": {
        "update_interval": 300,
        "request_timeout": 15,
    },
    "self_protect": {
        "check_interval": 120,
    },
    "tls": {
        "cert_file": "/opt/xdr/certs/xdr.pem",
        "key_file": "/opt/xdr/certs/xdr-key.pem",
        "min_version": "TLSv1.3",
    },
    "logging": {
        "level": "INFO",
        "file": None,
        "max_size": 10485760,
    },
}


# ── Singleton config ─────────────────────────────────────

_config: dict | None = None
_config_lock = Lock()
_config_path: Path | None = None


def _find_config_file() -> Path | None:
    """Find the first existing config file."""
    # Check env var first
    env_path = os.environ.get("XDR_CONFIG_FILE")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    for path in CONFIG_PATHS:
        if path.exists():
            return path
    return None


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, recursively for nested dicts."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _coerce_type(value: str, reference: Any) -> Any:
    """Coerce a string env var value to the type of the reference default."""
    if reference is None:
        return value if value.lower() not in ("none", "null", "") else None
    if isinstance(reference, bool):
        return value.lower() in ("true", "1", "yes", "on")
    if isinstance(reference, int):
        return int(value)
    if isinstance(reference, float):
        return float(value)
    return value


def _apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides.

    Format: XDR_<SECTION>_<KEY> = value
    Example: XDR_ENGINE_NIC_INTERFACE=eth0
    """
    for section_name, section_data in config.items():
        if not isinstance(section_data, dict):
            continue
        for key, default_val in section_data.items():
            env_key = f"XDR_{section_name.upper()}_{key.upper()}"
            env_val = os.environ.get(env_key)
            if env_val is not None:
                try:
                    config[section_name][key] = _coerce_type(env_val, default_val)
                    logger.info(f"Config override: {env_key} = {env_val}")
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid env override {env_key}={env_val}: {e}")
    return config


def _validate_config(config: dict) -> list[str]:
    """Validate configuration values. Returns list of warnings."""
    warnings = []

    # Port validation
    port = config.get("engine", {}).get("dashboard_port", 29992)
    if not (1024 <= port <= 65535):
        warnings.append(f"dashboard_port={port} is outside valid range (1024-65535)")

    # Cache validation
    cache = config.get("cache", {})
    if cache.get("conn_cache_max", 0) < 1000:
        warnings.append("conn_cache_max is very small (<1000), may impact performance")

    # Correlation validation
    corr = config.get("correlation", {})
    if corr.get("window_secs", 60) < 10:
        warnings.append("correlation window_secs < 10 may cause false negatives")

    # DNS validation
    dns = config.get("dns", {})
    if dns.get("dga_entropy_threshold", 3.8) > 5.0:
        warnings.append("dga_entropy_threshold > 5.0 will miss most DGA domains")

    # Logging level
    level = config.get("logging", {}).get("level", "INFO")
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if level.upper() not in valid_levels:
        warnings.append(f"Invalid logging level: {level}")

    return warnings


def load_config(force_reload: bool = False) -> dict:
    """Load and return the XDR configuration.

    Sources (in priority order):
      1. Environment variables (XDR_<SECTION>_<KEY>)
      2. YAML config file
      3. Hardcoded defaults
    """
    global _config, _config_path

    with _config_lock:
        if _config is not None and not force_reload:
            return _config

        import copy
        config = copy.deepcopy(DEFAULTS)

        # Try to load YAML
        config_file = _find_config_file()
        if config_file:
            try:
                import yaml
                with open(config_file) as f:
                    yaml_config = yaml.safe_load(f) or {}
                config = _deep_merge(config, yaml_config)
                _config_path = config_file
                logger.info(f"Config loaded from {config_file}")
            except ImportError:
                logger.warning("PyYAML not installed — using defaults only")
            except Exception as e:
                logger.error(f"Config file error: {e} — using defaults")
        else:
            logger.info("No config file found — using defaults")

        # Apply environment variable overrides
        config = _apply_env_overrides(config)

        # Validate
        warnings = _validate_config(config)
        for w in warnings:
            logger.warning(f"Config validation: {w}")

        _config = config
        return _config


def get_config() -> dict:
    """Get the current configuration (singleton)."""
    if _config is None:
        return load_config()
    return _config


def get_config_path() -> Path | None:
    """Get the path of the loaded config file."""
    return _config_path


def reload_config() -> dict:
    """Force reload the configuration."""
    return load_config(force_reload=True)
