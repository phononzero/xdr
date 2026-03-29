#!/usr/bin/env python3
"""
XDR YARA Scanner — Scans executable files against YARA rules on exec events.
Rules are loaded from /opt/xdr/rules/*.yar
"""

import os
import logging
from pathlib import Path
from threading import Lock

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python not available — YARA scanning disabled")

RULES_DIR = Path("/opt/xdr/rules")
ALERT_CRITICAL = 3
ALERT_WARNING = 2


class YARAScanner:
    """YARA rule scanner for executable files."""

    def __init__(self):
        self._lock = Lock()
        self._rules = None
        self._scan_cache = {}       # path -> (mtime, results)
        self._max_cache = 2000
        self._max_file_size = 50 * 1024 * 1024  # 50MB max scan size
        self._load_rules()

    def _load_rules(self):
        """Load all .yar files from rules directory."""
        if not YARA_AVAILABLE:
            return

        RULES_DIR.mkdir(parents=True, exist_ok=True)

        rule_files = {}
        for f in RULES_DIR.glob("*.yar"):
            try:
                ns = f.stem
                rule_files[ns] = str(f)
            except Exception as e:
                logging.warning(f"YARA rule skip {f}: {e}")

        if not rule_files:
            logging.info("No YARA rules found in %s", RULES_DIR)
            self._rules = None
            return

        try:
            self._rules = yara.compile(filepaths=rule_files)
            logging.info(f"YARA: loaded {len(rule_files)} rule file(s)")
        except yara.Error as e:
            logging.error(f"YARA compile error: {e}")
            self._rules = None

    def reload_rules(self):
        """Reload rules from disk."""
        with self._lock:
            self._load_rules()
            self._scan_cache.clear()

    def scan_file(self, path: str) -> list[dict] | None:
        """
        Scan a file against YARA rules.
        Returns list of matches or None if no matches / not scannable.
        """
        if not YARA_AVAILABLE or not self._rules:
            return None

        try:
            stat = os.stat(path)
            if stat.st_size > self._max_file_size:
                return None
            if stat.st_size == 0:
                return None

            # Cache check
            cache_key = path
            if cache_key in self._scan_cache:
                cached_mtime, cached_results = self._scan_cache[cache_key]
                if cached_mtime == stat.st_mtime:
                    return cached_results

            # Scan
            with self._lock:
                matches = self._rules.match(path, timeout=10)

            results = []
            for m in matches:
                results.append({
                    "rule": m.rule,
                    "namespace": m.namespace,
                    "tags": list(m.tags),
                    "meta": dict(m.meta) if m.meta else {},
                })

            # Cache result
            if len(self._scan_cache) < self._max_cache:
                self._scan_cache[cache_key] = (stat.st_mtime, results if results else None)

            return results if results else None

        except (OSError, PermissionError, yara.Error) as e:
            logging.debug(f"YARA scan error {path}: {e}")
            return None

    def scan_exec_event(self, path: str) -> dict | None:
        """
        Scan an executable from an exec event.
        Returns alert dict if YARA match found.
        """
        matches = self.scan_file(path)
        if not matches:
            return None

        # Determine severity from rule meta
        max_severity = ALERT_WARNING
        for m in matches:
            sev = m.get("meta", {}).get("severity", "warning")
            if sev == "critical" or "malware" in m.get("tags", []):
                max_severity = ALERT_CRITICAL

        rule_names = ", ".join(m["rule"] for m in matches)
        return {
            "action": "ALERT",
            "reason": "YARA_MATCH",
            "detail": f"YARA 매치: {rule_names} ({path})",
            "alert_level": max_severity,
            "path": path,
            "matches": matches,
        }


def create_default_rules():
    """Create default YARA rules if none exist."""
    RULES_DIR.mkdir(parents=True, exist_ok=True)

    default_rules = {
        "reverse_shell.yar": '''
rule ReverseShell_Bash {
    meta:
        description = "Bash reverse shell patterns"
        severity = "critical"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = "nc -e /bin" ascii
        $s4 = "ncat -e /bin" ascii
        $s5 = "mkfifo /tmp/" ascii
        $s6 = "socat exec:" ascii
    condition:
        any of them
}

rule ReverseShell_Python {
    meta:
        description = "Python reverse shell patterns"
        severity = "critical"
    strings:
        $s1 = "socket.socket" ascii
        $s2 = "subprocess.call" ascii
        $s3 = "pty.spawn" ascii
        $rev = /connect\s*\(\s*\(\s*["'][0-9]+\.[0-9]+/ ascii
    condition:
        ($s1 and $s3) or ($s1 and $s2 and $rev)
}
''',
        "cryptominer.yar": '''
rule CryptoMiner_Strings {
    meta:
        description = "Cryptocurrency miner indicators"
        severity = "critical"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "xmrig" ascii nocase
        $s4 = "monero" ascii nocase
        $s5 = "cryptonight" ascii nocase
        $s6 = "hashrate" ascii nocase
        $pool = /pool\.[a-z]+\.(com|org|net)/ ascii nocase
    condition:
        2 of them
}
''',
        "webshell.yar": '''
rule WebShell_PHP {
    meta:
        description = "PHP webshell patterns"
        severity = "critical"
    strings:
        $s1 = "eval(base64_decode" ascii nocase
        $s2 = "system($_" ascii nocase
        $s3 = "passthru($_" ascii nocase
        $s4 = "shell_exec($_" ascii nocase
        $s5 = "<?php eval($_POST" ascii nocase
    condition:
        any of them
}
''',
        "suspicious.yar": '''
rule Suspicious_ELF_Packer {
    meta:
        description = "Packed/obfuscated ELF binary"
        severity = "warning"
    strings:
        $elf = { 7f 45 4c 46 }
        $upx = "UPX!" ascii
        $packed = "This file is packed" ascii
    condition:
        $elf at 0 and ($upx or $packed)
}

rule Suspicious_Script_Download_Exec {
    meta:
        description = "Script that downloads and executes"
        severity = "warning"
    strings:
        $dl1 = "curl " ascii
        $dl2 = "wget " ascii
        $ex1 = "| bash" ascii
        $ex2 = "| sh" ascii
        $ex3 = "chmod +x" ascii
    condition:
        ($dl1 or $dl2) and ($ex1 or $ex2 or $ex3)
}
''',
    }

    for name, content in default_rules.items():
        path = RULES_DIR / name
        if not path.exists():
            path.write_text(content.strip() + "\n")
            logging.info(f"Created default YARA rule: {path}")
