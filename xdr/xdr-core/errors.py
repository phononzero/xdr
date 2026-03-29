#!/usr/bin/env python3
"""
XDR Structured Error System.

Provides typed exception classes with error codes for all XDR modules.
Each error has:
  - code:     Unique string identifier (e.g. "EBPF_LOAD_FAILED")
  - message:  Human-readable description
  - severity: DEBUG, WARNING, ERROR, CRITICAL
"""

import logging
from datetime import datetime

logger = logging.getLogger("xdr.errors")


class XDRError(Exception):
    """Base XDR error with structured error code."""

    def __init__(self, code: str, message: str, severity: str = "ERROR",
                 details: dict | None = None):
        self.code = code
        self.message = message
        self.severity = severity
        self.details = details or {}
        self.timestamp = datetime.now().isoformat()
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def log(self):
        """Log this error at the appropriate severity level."""
        log_fn = {
            "DEBUG": logger.debug,
            "INFO": logger.info,
            "WARNING": logger.warning,
            "ERROR": logger.error,
            "CRITICAL": logger.critical,
        }.get(self.severity, logger.error)
        log_fn(f"[{self.code}] {self.message}", extra={"error_details": self.details})


# ── eBPF Errors ──────────────────────────────────────────

class EBPFError(XDRError):
    """Errors related to eBPF program loading/operation."""
    pass


class EBPFLoadError(EBPFError):
    def __init__(self, program: str, reason: str = ""):
        super().__init__(
            code="EBPF_LOAD_FAILED",
            message=f"Failed to load eBPF program: {program}. {reason}",
            severity="CRITICAL",
            details={"program": program},
        )


class EBPFAttachError(EBPFError):
    def __init__(self, program: str, interface: str = "", reason: str = ""):
        super().__init__(
            code="EBPF_ATTACH_FAILED",
            message=f"Failed to attach eBPF program {program} to {interface}. {reason}",
            severity="CRITICAL",
            details={"program": program, "interface": interface},
        )


# ── Configuration Errors ──────────────────────────────────

class ConfigError(XDRError):
    """Errors related to configuration loading/validation."""
    pass


class ConfigFileNotFound(ConfigError):
    def __init__(self, path: str):
        super().__init__(
            code="CONFIG_FILE_NOT_FOUND",
            message=f"Configuration file not found: {path}",
            severity="WARNING",
            details={"path": path},
        )


class ConfigValidationError(ConfigError):
    def __init__(self, field: str, reason: str):
        super().__init__(
            code="CONFIG_VALIDATION_ERROR",
            message=f"Invalid config value for '{field}': {reason}",
            severity="ERROR",
            details={"field": field, "reason": reason},
        )


# ── Detection Errors ─────────────────────────────────────

class DetectionError(XDRError):
    """Errors in the detection pipeline."""
    pass


class RuleParseError(DetectionError):
    def __init__(self, rule_name: str, reason: str = ""):
        super().__init__(
            code="RULE_PARSE_ERROR",
            message=f"Failed to parse detection rule: {rule_name}. {reason}",
            severity="WARNING",
            details={"rule": rule_name},
        )


class BlockActionError(DetectionError):
    def __init__(self, pid: int, reason: str = ""):
        super().__init__(
            code="BLOCK_ACTION_FAILED",
            message=f"Failed to block/kill PID {pid}. {reason}",
            severity="WARNING",
            details={"pid": pid},
        )


# ── Forensic Errors ──────────────────────────────────────

class ForensicError(XDRError):
    """Errors during forensic evidence collection."""
    pass


class ForensicCollectionError(ForensicError):
    def __init__(self, pid: int, reason: str = ""):
        super().__init__(
            code="FORENSIC_COLLECTION_FAILED",
            message=f"Failed to collect forensic evidence for PID {pid}. {reason}",
            severity="WARNING",
            details={"pid": pid},
        )


class ForensicStorageError(ForensicError):
    def __init__(self, path: str, reason: str = ""):
        super().__init__(
            code="FORENSIC_STORAGE_ERROR",
            message=f"Failed to store evidence at {path}. {reason}",
            severity="ERROR",
            details={"path": path},
        )


# ── Network Errors ───────────────────────────────────────

class NetworkError(XDRError):
    """Errors related to network monitoring."""
    pass


class NICNotFoundError(NetworkError):
    def __init__(self, interface: str):
        super().__init__(
            code="NIC_NOT_FOUND",
            message=f"Network interface '{interface}' not found or not available",
            severity="CRITICAL",
            details={"interface": interface},
        )


class ThreatIntelError(NetworkError):
    def __init__(self, feed: str, reason: str = ""):
        super().__init__(
            code="THREAT_INTEL_FEED_ERROR",
            message=f"Failed to fetch threat intel feed '{feed}'. {reason}",
            severity="WARNING",
            details={"feed": feed},
        )


# ── Authentication Errors ────────────────────────────────

class AuthError(XDRError):
    """Errors related to API authentication."""
    pass


class AuthenticationFailed(AuthError):
    def __init__(self, ip: str, reason: str = ""):
        super().__init__(
            code="AUTH_FAILED",
            message=f"Authentication failed from {ip}. {reason}",
            severity="WARNING",
            details={"client_ip": ip},
        )


class TokenExpiredError(AuthError):
    def __init__(self):
        super().__init__(
            code="TOKEN_EXPIRED",
            message="JWT token has expired",
            severity="INFO",
        )


# ── Integrity Errors ─────────────────────────────────────

class IntegrityError(XDRError):
    """Errors during integrity monitoring."""
    pass


class BaselineError(IntegrityError):
    def __init__(self, reason: str = ""):
        super().__init__(
            code="INTEGRITY_BASELINE_ERROR",
            message=f"Failed to create/load integrity baseline. {reason}",
            severity="ERROR",
        )


class TamperingDetected(IntegrityError):
    def __init__(self, file_path: str, change_type: str = "modified"):
        super().__init__(
            code="FILE_TAMPERING_DETECTED",
            message=f"File tampering detected: {file_path} ({change_type})",
            severity="CRITICAL",
            details={"file": file_path, "type": change_type},
        )
