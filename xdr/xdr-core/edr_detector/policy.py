#!/usr/bin/env python3
"""
EDR Detector — Policy management (load/save/defaults).
"""

import json
import logging
from pathlib import Path

DETECTOR_CONFIG_FILE = Path("/opt/xdr/config/detector_policy.json")

DEFAULT_POLICY = {
    # Global auto-block toggle (False = alert only, True = auto kill/block)
    "auto_block": False,
    # Per-detector toggles (override global when set)
    "auto_block_memfd": None,       # None = follow global
    "auto_block_lolbins": None,
    "auto_block_ptrace": None,
    "auto_block_sequence": None,
    "auto_block_container_escape": None,
    "auto_block_rootkit": None,
    "auto_block_lateral": None,
    # LOLBins custom whitelist (comm patterns to ignore)
    "lolbins_whitelist": [],
    # ptrace whitelist (comms allowed to ptrace)
    "ptrace_whitelist": ["gdb", "strace", "ltrace"],
    # Allowed kernel modules (rootkit detection whitelist)
    "allowed_modules": [],
    # Internal scan threshold (ports/sec to trigger)
    "scan_threshold": 20,
    # Lateral movement whitelist (IPs that can SSH internally)
    "lateral_whitelist": [],
    # Whitelist / blacklist rules (managed via UI)
    "whitelist_rules": [],
    "blacklist_rules": [],
}


def _load_policy() -> dict:
    """Load detector policy from disk."""
    try:
        if DETECTOR_CONFIG_FILE.exists():
            with open(DETECTOR_CONFIG_FILE) as f:
                saved = json.load(f)
            policy = dict(DEFAULT_POLICY)
            policy.update(saved)
            return policy
    except (json.JSONDecodeError, OSError) as e:
        logging.warning(f"Failed to load detector policy: {e}")
    return dict(DEFAULT_POLICY)


def _save_policy(policy: dict):
    """Save detector policy to disk."""
    try:
        DETECTOR_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(DETECTOR_CONFIG_FILE, "w") as f:
            json.dump(policy, f, indent=2)
    except OSError as e:
        logging.error(f"Failed to save detector policy: {e}")
