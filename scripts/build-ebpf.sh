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
CORE_DIR="${PROJECT_ROOT}/xdr/xdr-core"

# SSL 프로브 eBPF 빌드 플래그
BPF_CFLAGS_SSL="-g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/bpf"

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

# ─── 3b. SSL 프로브 빌드 (xdr-core, Makefile 없음 — 직접 컴파일) ──────────
build_ssl_probe() {
    log_info "────────────────────────────────────────"
    log_info "SSL 프로브 (eBPF uprobe 평문 캡처) 빌드: ${CORE_DIR}/ssl_probe.bpf.c"

    local src="${CORE_DIR}/ssl_probe.bpf.c"
    local obj="${CORE_DIR}/ssl_probe.bpf.o"
    local vmh="${CORE_DIR}/vmlinux.h"

    if [[ ! -f "$src" ]]; then
        log_err "SSL 프로브 소스 없음: $src"
        return 1
    fi
    # vmlinux.h 보장
    if [[ ! -f "$vmh" ]]; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$vmh"
    fi

    if clang $BPF_CFLAGS_SSL -I"${CORE_DIR}" -c "$src" -o "$obj"; then
        log_ok "SSL 프로브 빌드 성공: $obj"
        file "$obj"
    else
        log_err "SSL 프로브 빌드 실패"
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

    # BPF Guard 오브젝트 설치 (ebpf-edr/Makefile 의 all 타깃이 이미 빌드함).
    # bpf_guard.py 는 /opt/xdr/xdr-core/bpf_guard.bpf.o 를 참조하므로 여기에 배치.
    if [[ -f "${EDR_DIR}/bpf_guard.bpf.o" ]]; then
        sudo mkdir -p "${INSTALL_DIR}/xdr-core"
        sudo cp "${EDR_DIR}/bpf_guard.bpf.o" "${INSTALL_DIR}/xdr-core/"
        log_ok "BPF Guard 설치됨: ${INSTALL_DIR}/xdr-core/bpf_guard.bpf.o"
    else
        log_warn "bpf_guard.bpf.o 없음 — BPF Guard 설치 건너뜀"
    fi

    # SSL 프로브 오브젝트 설치 (ssl_probe.py 가 /opt/xdr/xdr-core/ssl_probe.bpf.o 참조)
    if [[ -f "${CORE_DIR}/ssl_probe.bpf.o" ]]; then
        sudo mkdir -p "${INSTALL_DIR}/xdr-core"
        sudo cp "${CORE_DIR}/ssl_probe.bpf.o" "${INSTALL_DIR}/xdr-core/"
        log_ok "SSL 프로브 설치됨: ${INSTALL_DIR}/xdr-core/ssl_probe.bpf.o"
    else
        log_warn "ssl_probe.bpf.o 없음 — SSL 프로브 설치 건너뜀"
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
    build_ssl_probe || fail=1

    if [[ $fail -eq 0 ]]; then
        install_objects
        summary
    else
        log_err "일부 빌드가 실패했습니다. 위 로그를 확인해주세요."
        exit 1
    fi
}

main "$@"
