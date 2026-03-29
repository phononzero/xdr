#!/bin/bash
# ═══════════════════════════════════════════════════════
# XDR Safe Mode Installation Script
# 위험 기능(커널 lockdown, BPF 제한 등) 없이 순수 XDR만 설치
# ═══════════════════════════════════════════════════════
set -euo pipefail

XDR_DIR="/opt/xdr"
SCRIPT_DIR="$(cd "$(dirname "$0")/xdr" && pwd)"

echo "🛡️ XDR MVP 설치 스크립트 (Safe Mode 기반)"
echo "════════════════════════════════════════"
echo "  ℹ 안정성을 위해 순수 XDR 기능 위주로 설치합니다"
echo "════════════════════════════════════════"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "❌ root 권한이 필요합니다: sudo $0"
    exit 1
fi

# 1. 디렉토리 구조 생성
echo "[1/7] 디렉토리 구조 생성..."
mkdir -p "$XDR_DIR"/{xdr-core,ebpf-edr,xdp-ndr,certs,forensics,integrity/baselines,integrity/diffs,dns,threat_intel,config,yara_rules}

# 2. Python 파일 복사
echo "[2/7] XDR Core 파일 복사..."
cp -r "$SCRIPT_DIR/xdr-core/"*.py "$XDR_DIR/xdr-core/" 2>/dev/null || true
cp -r "$SCRIPT_DIR/xdr-core/"*.yaml "$XDR_DIR/xdr-core/" 2>/dev/null || true

# API, Engine, Detector 서브패키지 복사
for subdir in api engine edr_detector; do
    if [[ -d "$SCRIPT_DIR/xdr-core/$subdir" ]]; then
        cp -r "$SCRIPT_DIR/xdr-core/$subdir" "$XDR_DIR/xdr-core/"
        echo "  ✅ $subdir/ 복사 완료"
    fi
done

# Static 파일 (대시보드 SPA 빌드)
if [[ -d "$SCRIPT_DIR/xdr-core/static" ]]; then
    cp -r "$SCRIPT_DIR/xdr-core/static" "$XDR_DIR/xdr-core/"
    echo "  ✅ static/ 복사 완료"
fi

# Docs
if [[ -d "$SCRIPT_DIR/xdr-core/docs" ]]; then
    cp -r "$SCRIPT_DIR/xdr-core/docs" "$XDR_DIR/xdr-core/"
fi

# 3. eBPF 오브젝트 복사
echo "[3/7] eBPF 오브젝트 복사..."
if [[ -f "$SCRIPT_DIR/ebpf-edr/edr.bpf.o" ]]; then
    cp "$SCRIPT_DIR/ebpf-edr/edr.bpf.o" "$XDR_DIR/ebpf-edr/"
    echo "  ✅ EDR eBPF 복사 완료 ($(du -h "$SCRIPT_DIR/ebpf-edr/edr.bpf.o" | cut -f1))"
else
    echo "  ⚠ EDR eBPF 오브젝트 없음 — 빌드 필요: cd $SCRIPT_DIR/ebpf-edr && make"
fi

if [[ -f "$SCRIPT_DIR/xdp-ndr/ndr.bpf.o" ]]; then
    cp "$SCRIPT_DIR/xdp-ndr/ndr.bpf.o" "$XDR_DIR/xdp-ndr/"
    echo "  ✅ NDR XDP 복사 완료 ($(du -h "$SCRIPT_DIR/xdp-ndr/ndr.bpf.o" | cut -f1))"
else
    echo "  ⚠ NDR XDP 오브젝트 없음 — 빌드 필요: cd $SCRIPT_DIR/xdp-ndr && make"
fi

# BPF guard는 복사하지 않음 (MVP 지원 안함)
echo "  ℹ BPF Guard 스킵 (MVP에서 비활성화)"

# 4. 대시보드 복사
echo "[4/7] 대시보드 복사..."
if [[ -d "$SCRIPT_DIR/dashboard/dist" ]]; then
    mkdir -p "$XDR_DIR/dashboard"
    cp -r "$SCRIPT_DIR/dashboard/dist" "$XDR_DIR/dashboard/"
    echo "  ✅ 대시보드 빌드 복사 완료"
else
    echo "  ⚠ 대시보드 빌드 없음 — 빌드 필요: cd $SCRIPT_DIR/dashboard && npm ci && npm run build"
fi

# 5. TLS 인증서 생성 (없을 경우)
echo "[5/7] TLS 인증서 확인..."
if [[ ! -f "$XDR_DIR/certs/xdr.pem" ]]; then
    echo "  → 자체 서명 인증서 생성중..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$XDR_DIR/certs/xdr-key.pem" \
        -out "$XDR_DIR/certs/xdr.pem" \
        -days 365 \
        -subj "/CN=XDR/O=XDR Security" 2>/dev/null
    chmod 600 "$XDR_DIR/certs/xdr-key.pem"
    echo "  ✅ 인증서 생성 완료"
else
    echo "  ✅ 기존 인증서 사용"
fi

# 6. systemd 서비스 등록
echo "[6/7] systemd 서비스 등록..."
cat > /etc/systemd/system/xdr-safe.service << 'EOF'
[Unit]
Description=XDR Detection Engine
After=network.target
Documentation=file:///opt/xdr/xdr-core/docs/

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/xdr/xdr-core/xdr_safe_mode.py
WorkingDirectory=/opt/xdr/xdr-core
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=xdr-safe

# 보안 (최소한)
ProtectHome=read-only
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF

# 기존 위험한 서비스 비활성화 (존재할 경우)
systemctl disable kernel-lockdown.service 2>/dev/null || true
systemctl stop kernel-lockdown.service 2>/dev/null || true
systemctl disable xdr-dashboard.service 2>/dev/null || true

systemctl daemon-reload
echo "  ✅ xdr-safe.service 등록 완료"

# ⚠ 99-xdr-hardening.conf는 설치하지 않음!
echo "  ℹ sysctl 하드닝(99-xdr-hardening.conf) 스킵"
# 기존에 설치되어 있다면 제거
if [[ -f /etc/sysctl.d/99-xdr-hardening.conf ]]; then
    rm -f /etc/sysctl.d/99-xdr-hardening.conf
    sysctl --system > /dev/null 2>&1 || true
    echo "  ⚠ 기존 99-xdr-hardening.conf 제거됨"
fi

# 7. 권한 설정
echo "[7/7] 권한 설정..."
chown -R root:root "$XDR_DIR"
chmod 755 "$XDR_DIR"
chmod 755 "$XDR_DIR/xdr-core"

echo ""
echo "════════════════════════════════════════"
echo "✅ XDR 설치 완료!"
echo ""
echo "  디렉토리: $XDR_DIR"
echo "  실행:     sudo python3 $XDR_DIR/xdr-core/xdr_safe_mode.py"
echo "  서비스:   sudo systemctl start xdr-safe"
echo "  자동시작: sudo systemctl enable xdr-safe"
echo "  대시보드: https://127.0.0.1:29992"
echo ""
echo "  비활성화된 기능:"
echo "    ❌ 커널 Lockdown"
echo "    ❌ BPF Guard (eBPF 접근 제한)"
echo "    ❌ sysctl 하드닝"
echo "    ❌ 패키지 모니터"
echo "    ❌ 커널 보안 자동 복구"
echo ""
echo "  활성 기능:"
echo "    ✅ eBPF EDR (프로세스/파일/네트 감시)"
echo "    ✅ XDP NDR (네트워크 분석)"
echo "    ✅ XDR 상관분석 + YARA + DNS + TLS"
echo "    ✅ 위협 인텔리전스 + 포렌식"
echo "    ✅ 웹 대시보드 + 데스크톱 알림"
echo "════════════════════════════════════════"
