#!/usr/bin/env bash
###############################################################################
# build-ebpf.sh — XDR eBPF 프로그램 빌드 스크립트
# EDR (Endpoint Detection) + NDR (Network Detection) eBPF 오브젝트 빌드
###############################################################################
set -euo pipefail

# bpftool은 /usr/sbin에 설치되므로 PATH에 추가
export PATH="/usr/sbin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# eBPF 소스 디렉토리
EDR_DIR="${PROJECT_ROOT}/xdr/ebpf-edr"
NDR_DIR="${PROJECT_ROOT}/xdr/xdp-ndr"

# 배포 대상 디렉토리
INSTALL_DIR="/opt/xdr"

# 색상 출력
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── 1. 필수 도구 확인 ───────────────────────────────────────────────────
check_prerequisites() {
    log_info "필수 도구 확인 중..."
    local missing=0

    for cmd in clang bpftool llc; do
        if command -v "$cmd" &>/dev/null; then
            log_ok "$cmd: $(command -v "$cmd")"
        else
            log_err "$cmd 을(를) 찾을 수 없습니다"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        log_err "필수 도구가 부족합니다. 설치: sudo apt install clang llvm bpftool libbpf-dev"
        exit 1
    fi
}

# ─── 2. 커널 BTF 지원 확인 ───────────────────────────────────────────────
check_btf() {
    log_info "커널 BTF 지원 확인 중..."


    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        log_ok "BTF vmlinux 발견: /sys/kernel/btf/vmlinux"
    else
        log_err "BTF vmlinux을 찾을 수 없습니다. CONFIG_DEBUG_INFO_BTF=y 커널이 필요합니다."
        exit 1
    fi

    log_info "커널: $(uname -r)"
}

# ─── 3. eBPF 빌드 ────────────────────────────────────────────────────────
build_component() {
    local name="$1"
    local dir="$2"
    local obj="$3"

    log_info "────────────────────────────────────────"
    log_info "${name} 빌드 시작: ${dir}"

    if [[ ! -d "$dir" ]]; then
        log_err "디렉토리를 찾을 수 없습니다: $dir"
        return 1
    fi

    # 이전 빌드 정리
    make -C "$dir" clean 2>/dev/null || true

    # 빌드 실행
    if make -C "$dir"; then
        if [[ -f "${dir}/${obj}" ]]; then
            log_ok "${name} 빌드 성공: ${dir}/${obj}"
            file "${dir}/${obj}"
        else
            log_err "${name} 빌드 산출물을 찾을 수 없습니다: ${dir}/${obj}"
            return 1
        fi
    else
        log_err "${name} 빌드 실패"
        return 1
    fi
}

# ─── 4. 배포 설치 ────────────────────────────────────────────────────────
install_objects() {
    log_info "────────────────────────────────────────"
    log_info "빌드 산출물을 ${INSTALL_DIR} 에 설치 중..."

    sudo mkdir -p "${INSTALL_DIR}/ebpf-edr" "${INSTALL_DIR}/xdp-ndr"

    if [[ -f "${EDR_DIR}/edr.bpf.o" ]]; then
        sudo cp "${EDR_DIR}/edr.bpf.o" "${INSTALL_DIR}/ebpf-edr/"
        log_ok "EDR 설치됨: ${INSTALL_DIR}/ebpf-edr/edr.bpf.o"
    fi

    if [[ -f "${NDR_DIR}/ndr.bpf.o" ]]; then
        sudo cp "${NDR_DIR}/ndr.bpf.o" "${INSTALL_DIR}/xdp-ndr/"
        log_ok "NDR 설치됨: ${INSTALL_DIR}/xdp-ndr/ndr.bpf.o"
    fi

    # build-ebpf.sh 자체도 /opt/xdr 에 복사 (xdr_engine.py 참조 경로)
    sudo cp "$0" "${INSTALL_DIR}/build-ebpf.sh"
    sudo chmod +x "${INSTALL_DIR}/build-ebpf.sh"
    log_ok "빌드 스크립트 설치됨: ${INSTALL_DIR}/build-ebpf.sh"
}

# ─── 5. 결과 요약 ────────────────────────────────────────────────────────
summary() {
    echo ""
    log_info "════════════════════════════════════════"
    log_info "  XDR eBPF 빌드 완료 요약"
    log_info "════════════════════════════════════════"
    echo ""

    for obj in "${EDR_DIR}/edr.bpf.o" "${NDR_DIR}/ndr.bpf.o"; do
        if [[ -f "$obj" ]]; then
            log_ok "$(basename "$obj") — $(du -h "$obj" | cut -f1) — $(file -b "$obj")"
        else
            log_err "$(basename "$obj") — 빌드되지 않음"
        fi
    done

    echo ""
    log_info "배포 경로: ${INSTALL_DIR}/"
    log_info "커널: $(uname -r)"
    log_info "다음 단계: systemctl start xdr-engine 또는 python3 xdr_engine.py"
    log_info "════════════════════════════════════════"
}

# ─── Main ─────────────────────────────────────────────────────────────────
main() {
    echo ""
    log_info "XDR eBPF 빌드 스크립트 시작"
    echo ""

    check_prerequisites
    check_btf

    local fail=0
    build_component "EDR (eBPF Endpoint Detection)" "$EDR_DIR" "edr.bpf.o" || fail=1
    build_component "NDR (XDP Network Detection)"   "$NDR_DIR" "ndr.bpf.o" || fail=1

    if [[ $fail -eq 0 ]]; then
        install_objects
        summary
    else
        log_err "일부 빌드가 실패했습니다. 위 로그를 확인해주세요."
        exit 1
    fi
}

main "$@"
