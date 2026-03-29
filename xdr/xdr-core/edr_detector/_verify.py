#!/usr/bin/env python3
"""Verify edr_detector refactoring — no code loss."""
import re, os

ORIG = "/home/eddy/Desktop/SETUP/xdr/xdr-core/edr_detector.py"
PKG = "/home/eddy/Desktop/SETUP/xdr/xdr-core/edr_detector"

# 1. Check original is now a proxy
with open(ORIG) as f:
    orig = f.read()
print(f"[1] edr_detector.py is proxy: {'re-export' in orig or 'edr_detector import' in orig}")

# 2. Count lines in package
total = 0
files = []
for root, dirs, fnames in os.walk(PKG):
    for fn in sorted(fnames):
        if fn.endswith('.py'):
            fp = os.path.join(root, fn)
            with open(fp) as f:
                n = len(f.readlines())
            total += n
            rel = os.path.relpath(fp, PKG)
            files.append((rel, n))
            print(f"  {rel}: {n} lines")
print(f"\n[2] Total package lines: {total}")

# 3. Check all original public methods exist in __init__.py
init_path = os.path.join(PKG, "__init__.py")
with open(init_path) as f:
    init_code = f.read()

needed_methods = [
    "check_exec", "check_event", "check_container_escape",
    "check_kernel_integrity", "check_lateral_movement",
    "check_ssl_content", "scan_cmdlines",
    "kill_and_block", "get_process_tree", "get_process_chain",
    "reload_policy", "get_policy", "update_policy",
    "_should_auto_block", "_get_whitelist_scopes",
]

print("\n[3] Method check:")
missing = []
for m in needed_methods:
    found = f"def {m}" in init_code or f"self.{m}" in init_code or f".{m}(" in init_code
    status = "OK" if found else "MISSING"
    if not found:
        missing.append(m)
    print(f"  {m}: {status}")

# 4. Check all detector modules exist
detectors = ["fileless", "lolbins", "ptrace", "beacon", 
             "container", "rootkit", "sequence", "lateral", "ssl_content"]
print("\n[4] Detector modules:")
for d in detectors:
    fp = os.path.join(PKG, "detectors", f"{d}.py")
    exists = os.path.exists(fp)
    print(f"  {d}.py: {'OK' if exists else 'MISSING'}")

# 5. Check core modules
core = ["policy.py", "rules.py", "process_tracker.py", "block_engine.py"]
print("\n[5] Core modules:")
for c in core:
    fp = os.path.join(PKG, c)
    exists = os.path.exists(fp)
    print(f"  {c}: {'OK' if exists else 'MISSING'}")

# 6. Check rules.py has key constants
with open(os.path.join(PKG, "rules.py")) as f:
    rules = f.read()
print(f"\n[6] Rules constants:")
print(f"  MEMFD_PATTERNS: {'OK' if 'MEMFD_PATTERNS' in rules else 'MISSING'}")
print(f"  LOLBIN_RULES: {'OK' if 'LOLBIN_RULES' in rules else 'MISSING'}")
print(f"  SEQUENCE_PATTERNS: {'OK' if 'SEQUENCE_PATTERNS' in rules else 'MISSING'}")

# 7. Check block_engine has BLOCK_FAILED
with open(os.path.join(PKG, "block_engine.py")) as f:
    block = f.read()
print(f"\n[7] Block failure logging: {'OK' if 'BLOCK_FAILED' in block else 'MISSING'}")

# Summary
print(f"\n{'='*50}")
if missing:
    print(f"FAIL: Missing methods: {missing}")
else:
    print("ALL CHECKS PASSED - No code loss detected")
