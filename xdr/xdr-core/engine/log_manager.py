"""
XDR Log Manager — Manages critical and general log rotation.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path

# Log directories
LOG_DIR = Path("/var/log/xdr")
CRITICAL_LOG_DIR = LOG_DIR / "critical"
GENERAL_LOG_DIR = LOG_DIR / "general"

CRITICAL_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB per file
CRITICAL_MAX_FILES = 10                      # 10 files * 100MB = 1GB max
GENERAL_RETENTION_DAYS = 3


class LogManager:
    """Manages XDR log rotation per the defined policy."""

    def __init__(self):
        CRITICAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
        GENERAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._critical_file_idx = self._find_current_critical_idx()
        self._critical_file = None
        self._critical_written = 0
        self._open_critical_file()

    def _find_current_critical_idx(self) -> int:
        existing = sorted(CRITICAL_LOG_DIR.glob("alert_*.log"))
        if not existing:
            return 1
        last = existing[-1].stem.split("_")[1]
        return int(last)

    def _open_critical_file(self):
        if self._critical_file:
            self._critical_file.close()
        path = CRITICAL_LOG_DIR / f"alert_{self._critical_file_idx:02d}.log"
        if path.exists():
            self._critical_written = path.stat().st_size
        else:
            self._critical_written = 0
        self._critical_file = open(path, "a")

    def write_critical(self, message: str):
        line = f"[{datetime.now().isoformat()}] {message}\n"
        encoded = line.encode("utf-8")

        if self._critical_written + len(encoded) > CRITICAL_MAX_FILE_SIZE:
            self._critical_file_idx += 1
            if self._critical_file_idx > CRITICAL_MAX_FILES:
                self._rotate_critical()
                self._critical_file_idx = CRITICAL_MAX_FILES
            self._open_critical_file()
            self._critical_written = 0

        self._critical_file.write(line)
        self._critical_file.flush()
        self._critical_written += len(encoded)

    def _rotate_critical(self):
        """Delete oldest, shift all files down by 1."""
        oldest = CRITICAL_LOG_DIR / "alert_01.log"
        if oldest.exists():
            oldest.unlink()
        for i in range(2, CRITICAL_MAX_FILES + 1):
            src = CRITICAL_LOG_DIR / f"alert_{i:02d}.log"
            dst = CRITICAL_LOG_DIR / f"alert_{i-1:02d}.log"
            if src.exists():
                src.rename(dst)

    def write_general(self, message: str):
        today = datetime.now().strftime("%Y-%m-%d")
        path = GENERAL_LOG_DIR / f"{today}.log"
        with open(path, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {message}\n")

    def cleanup_general(self):
        """Delete general logs older than GENERAL_RETENTION_DAYS."""
        cutoff = datetime.now() - timedelta(days=GENERAL_RETENTION_DAYS)
        for logfile in GENERAL_LOG_DIR.glob("*.log"):
            try:
                datestr = logfile.stem
                file_date = datetime.strptime(datestr, "%Y-%m-%d")
                if file_date < cutoff:
                    logfile.unlink()
            except (ValueError, OSError):
                pass

    def close(self):
        if self._critical_file:
            self._critical_file.close()
