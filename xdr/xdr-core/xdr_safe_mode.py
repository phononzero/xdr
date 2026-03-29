#!/usr/bin/env python3
"""
XDR Safe Mode Launcher — 위험 기능을 비활성화하고 순수 XDR 탐지만 실행.

비활성화 대상:
  1. LockdownManager — 커널 lockdown 활성화 방지
  2. BPFGuard — eBPF 접근 제한 방지
  3. SelfProtect._check_kernel_security() — lockdown 자동 재활성화 방지
  4. PackageMonitor.start() — 패키지 변경 감시 비활성화
  5. _activate_kernel_hardening() — sysctl 강제 설정 방지

유지 기능:
  - eBPF EDR (프로세스/파일/네트워크 감시)
  - XDP NDR (네트워크 패킷 분석)
  - XDR 상관분석 엔진
  - YARA 스캐너
  - DNS 모니터 (DGA/터널링 탐지)
  - TLS 핑거프린트
  - SSL 프로브
  - 파일 감사
  - 위협 인텔리전스 피드
  - 메모리 포렌식 스캐너
  - 무결성 모니터
  - 웹 대시보드 + 데스크톱 알림
  - 포렌식 수집
  - Self-Protect 파일 무결성 체크 (커널 체크만 제거)
"""

import sys
import os
import logging

# ── 로깅 먼저 설정 ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [XDR-SAFE] %(message)s"
)
logger = logging.getLogger("xdr.safe_mode")

logger.info("=" * 60)
logger.info("  XDR Safe Mode — 위험 기능 비활성화 모드")
logger.info("=" * 60)


# ── 1. LockdownManager → No-op 더미 ────────────────────
class DummyLockdownManager:
    """LockdownManager를 대체하는 no-op 클래스."""

    def __init__(self, **kwargs):
        logger.info("[SAFE] LockdownManager 비활성화됨 (커널 lockdown 건너뜀)")

    def execute(self):
        logger.info("[SAFE] LockdownManager.execute() → SKIP")
        return None

    @property
    def is_locked_down(self):
        return False

    def get_status(self):
        return {
            "lockdown_active": False,
            "blocked_modules": [],
            "known_modules_count": 0,
            "loaded_modules_count": 0,
            "safe_mode": True,
        }


# ── 2. BPFGuard → No-op 더미 ───────────────────────────
class DummyBPFGuard:
    """BPFGuard를 대체하는 no-op 클래스."""

    def __init__(self):
        logger.info("[SAFE] BPFGuard 비활성화됨 (eBPF 접근 제한 없음)")

    def load(self):
        return False

    def register_pid(self, pid):
        return True

    def enable(self):
        return False

    def disable(self):
        return True

    def get_stats(self):
        return {"allowed": 0, "denied": 0, "safe_mode": True}

    def unload(self):
        pass

    @property
    def is_loaded(self):
        return False

    @property
    def is_enforcing(self):
        return False


# ── Monkey-patch 적용 ───────────────────────────────────

# 3. lockdown_manager 모듈을 더미로 교체
import types
lockdown_mod = types.ModuleType("lockdown_manager")
lockdown_mod.LockdownManager = DummyLockdownManager
sys.modules["lockdown_manager"] = lockdown_mod
logger.info("[SAFE] lockdown_manager 모듈 → DummyLockdownManager로 교체")

# 4. bpf_guard 모듈을 더미로 교체
bpf_guard_mod = types.ModuleType("bpf_guard")
bpf_guard_mod.BPFGuard = DummyBPFGuard
sys.modules["bpf_guard"] = bpf_guard_mod
logger.info("[SAFE] bpf_guard 모듈 → DummyBPFGuard로 교체")


# ── 이제 원본 모듈 임포트 ───────────────────────────────
# xdr-core 디렉토리를 PYTHONPATH에 추가
xdr_core_dir = os.path.dirname(os.path.abspath(__file__))
if xdr_core_dir not in sys.path:
    sys.path.insert(0, xdr_core_dir)

# 5. PackageMonitor.start() → no-op 패치
from package_monitor import PackageMonitor

_orig_pkg_start = PackageMonitor.start


def _safe_pkg_start(self):
    logger.info("[SAFE] PackageMonitor.start() → SKIP (패키지 감시 비활성화)")

PackageMonitor.start = _safe_pkg_start
PackageMonitor.stop = lambda self: None
logger.info("[SAFE] PackageMonitor.start() → no-op으로 패치")


# 6. SelfProtect._check_kernel_security() → 빈 리스트 반환
from self_protect import SelfProtect

_orig_kernel_check = SelfProtect._check_kernel_security


def _safe_kernel_check(self):
    """커널 보안 체크 스킵 — lockdown 자동 재활성화 방지."""
    return []

SelfProtect._check_kernel_security = _safe_kernel_check
logger.info("[SAFE] SelfProtect._check_kernel_security() → [] (커널 체크 비활성화)")


# 7. XDREngine._activate_kernel_hardening() → no-op
# 이 메서드는 XDREngine 클래스에서 직접 패치
import xdr_engine

_orig_hardening = xdr_engine.XDREngine._activate_kernel_hardening


def _safe_hardening(self):
    logger.info("[SAFE] _activate_kernel_hardening() → SKIP (sysctl 하드닝 건너뜀)")

xdr_engine.XDREngine._activate_kernel_hardening = _safe_hardening
logger.info("[SAFE] XDREngine._activate_kernel_hardening() → no-op으로 패치")


# ── 시작 ────────────────────────────────────────────────
logger.info("[SAFE] 모든 위험 기능 비활성화 완료. XDR 엔진 시작...")
logger.info("[SAFE] 유지 기능: EDR, NDR, 상관분석, YARA, DNS, TLS, SSL, "
            "파일감사, 위협인텔, 메모리스캔, 무결성, 대시보드, 포렌식")
logger.info("=" * 60)


def main():
    engine = xdr_engine.XDREngine()
    engine.run()


if __name__ == "__main__":
    main()
