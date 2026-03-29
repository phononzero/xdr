# XDR 설치 가이드

## 목차
1. [사전 요구사항](#1-사전-요구사항)
2. [커스텀 커널 빌드 (선택)](#2-커스텀-커널-빌드-선택)
3. [eBPF 프로그램 빌드](#3-ebpf-프로그램-빌드)
4. [XDR 코어 설치](#4-xdr-코어-설치)
5. [대시보드 빌드 (선택)](#5-대시보드-빌드-선택)
6. [서비스 등록 및 실행](#6-서비스-등록-및-실행)
7. [설정](#7-설정)
8. [트러블슈팅](#8-트러블슈팅)

---

## 1. 사전 요구사항

### 필수 패키지

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y \
    clang llvm bpftool libbpf-dev linux-headers-$(uname -r) \
    python3 python3-venv python3-pip \
    openssl curl
```

### 커널 요구사항

BPF LSM이 활성화된 Linux 6.1 이상 커널이 필요합니다.

```bash
# BTF 지원 확인
ls /sys/kernel/btf/vmlinux    # 파일 존재 필수

# BPF LSM 확인
cat /sys/kernel/security/lsm  # "bpf"가 포함되어야 함

# 커널 버전 확인
uname -r                      # 6.1 이상
```

BTF가 없거나 BPF LSM이 비활성화된 경우, [커스텀 커널 빌드](#2-커스텀-커널-빌드-선택)가 필요합니다.

---

## 2. 커스텀 커널 빌드 (선택)

> 이미 BTF + BPF LSM이 활성화된 커널을 사용 중이라면 이 단계를 건너뛰세요.

### 2.1 빌드 의존성

```bash
sudo apt install -y \
    build-essential libncurses-dev bison flex \
    libssl-dev libelf-dev bc dwarves wget
```

### 2.2 커널 소스 다운로드

```bash
KERNEL_VERSION="6.12.77"  # 또는 원하는 LTS 버전
cd /usr/src
wget "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
tar xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"
```

### 2.3 설정 적용

```bash
# defconfig 기반으로 XDR 커널 프래그먼트 병합
make defconfig
./scripts/kconfig/merge_config.sh -m .config /path/to/xdr/kernel/kernel.config
make olddefconfig
```

> **참고**: `kernel/kernel.config`는 전체 `.config`가 아닌 프래그먼트(fragment)입니다.
> 특정 하드웨어(AMD Zen, Realtek R8169 등)에 최적화된 설정이 포함되어 있으므로,
> 본인 환경에 맞게 수정해주세요.

### 2.4 빌드 및 설치

```bash
make -j$(nproc)
sudo make modules_install
sudo make install
sudo update-grub
sudo reboot
```

---

## 3. eBPF 프로그램 빌드

### 3.1 vmlinux.h 생성

```bash
# 현재 커널의 BTF에서 vmlinux.h 자동 생성
bpftool btf dump file /sys/kernel/btf/vmlinux format c > xdr/ebpf-edr/vmlinux.h
cp xdr/ebpf-edr/vmlinux.h xdr/xdp-ndr/vmlinux.h
cp xdr/ebpf-edr/vmlinux.h xdr/xdr-core/vmlinux.h
```

### 3.2 빌드 실행

```bash
# 통합 빌드 스크립트 사용
sudo bash scripts/build-ebpf.sh
```

또는 개별 빌드:

```bash
# EDR eBPF
cd xdr/ebpf-edr && make && cd ../..

# NDR XDP
cd xdr/xdp-ndr && make && cd ../..
```

### 3.3 빌드 확인

```bash
file xdr/ebpf-edr/edr.bpf.o    # "ELF 64-bit LSB relocatable, eBPF"
file xdr/xdp-ndr/ndr.bpf.o     # "ELF 64-bit LSB relocatable, eBPF"
```

---

## 4. XDR 코어 설치

### 자동 설치 (권장)

```bash
sudo bash xdr/scripts/install_safe.sh
```

이 스크립트가 수행하는 작업:
1. `/opt/xdr/` 디렉토리 구조 생성
2. Python 코어 파일 복사
3. eBPF 오브젝트 복사
4. 대시보드 빌드 복사
5. TLS 자체 서명 인증서 생성
6. systemd `xdr-safe.service` 등록

### 수동 설치

```bash
# 디렉토리 생성
sudo mkdir -p /opt/xdr/{xdr-core,ebpf-edr,xdp-ndr,certs,forensics,yara_rules}
sudo mkdir -p /opt/xdr/integrity/{baselines,diffs}
sudo mkdir -p /opt/xdr/{dns,threat_intel,config}

# 파일 복사
sudo cp -r xdr/xdr-core/*.py /opt/xdr/xdr-core/
sudo cp -r xdr/xdr-core/*.yaml /opt/xdr/xdr-core/
sudo cp -r xdr/xdr-core/{api,engine,edr_detector,static} /opt/xdr/xdr-core/
sudo cp xdr/ebpf-edr/edr.bpf.o /opt/xdr/ebpf-edr/
sudo cp xdr/xdp-ndr/ndr.bpf.o /opt/xdr/xdp-ndr/

# TLS 인증서 생성
sudo openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /opt/xdr/certs/xdr-key.pem \
    -out /opt/xdr/certs/xdr.pem \
    -days 365 -subj "/CN=XDR/O=XDR Security"
sudo chmod 600 /opt/xdr/certs/xdr-key.pem

# 권한 설정
sudo chown -R root:root /opt/xdr
sudo chmod 755 /opt/xdr /opt/xdr/xdr-core
```

---

## 5. 대시보드 빌드 (선택)

```bash
cd xdr/dashboard
npm ci
npm run build

# 빌드 결과를 XDR 설치 경로로 복사
sudo mkdir -p /opt/xdr/dashboard
sudo cp -r dist /opt/xdr/dashboard/
```

> 대시보드 없이도 XDR 코어 엔진은 정상 동작합니다.
> API를 통해 모든 기능을 사용할 수 있습니다.

---

## 6. 서비스 등록 및 실행

### Safe Mode (권장)

```bash
# 서비스 시작
sudo systemctl start xdr-safe

# 부팅 시 자동 시작
sudo systemctl enable xdr-safe

# 상태 확인
sudo systemctl status xdr-safe

# 실시간 로그
sudo journalctl -u xdr-safe -f
```

### 직접 실행

```bash
sudo python3 /opt/xdr/xdr-core/xdr_safe_mode.py
```

### Safe Mode vs Full Mode

| 기능 | Safe Mode | Full Mode |
|------|:---------:|:---------:|
| eBPF EDR (프로세스/파일/네트워크) | ✅ | ✅ |
| XDP NDR (패킷 필터) | ✅ | ✅ |
| 상관분석 + YARA + DNS + TLS | ✅ | ✅ |
| 위협 인텔리전스 + 포렌식 | ✅ | ✅ |
| 웹 대시보드 + 데스크톱 알림 | ✅ | ✅ |
| 커널 Lockdown | ❌ | ✅ |
| BPF Guard (eBPF 접근 제한) | ❌ | ✅ |
| sysctl 하드닝 자동 적용 | ❌ | ✅ |
| 패키지 모니터 | ❌ | ✅ |

> Safe Mode는 위험 기능(커널 lockdown, BPF 접근 제한)을 비활성화하여
> 시스템 안정성을 보장하면서 XDR 탐지 기능을 모두 사용할 수 있습니다.

---

## 7. 설정

### 설정 파일: `xdr_config.yaml`

```yaml
engine:
  nic_interface: "auto"      # "auto" = 자동 감지, 또는 "eth0" 등 명시적 지정
  dashboard_port: 29992      # HTTPS 대시보드 포트
  xdr_dir: "/opt/xdr"        # XDR 설치 경로

cache:
  conn_cache_max: 500000     # 연결 캐시 최대 크기
  proc_cache_max: 1500000    # 프로세스 캐시 최대 크기
  event_history_max: 5000    # 이벤트 히스토리 최대 크기

correlation:
  window_secs: 60            # 상관분석 시간 창 (초)
  beacon_detect_count: 10    # 비콘 감지 최소 횟수

dns:
  dga_entropy_threshold: 3.8 # DGA 엔트로피 임계값
  tunnel_txt_threshold: 10   # DNS 터널링 TXT 임계값
```

### 환경변수 오버라이드

설정 파일의 모든 값은 환경변수로 오버라이드 가능합니다:

```bash
export XDR_ENGINE_NIC_INTERFACE=eth0
export XDR_ENGINE_DASHBOARD_PORT=8443
export XDR_CACHE_CONN_CACHE_MAX=100000
```

### sysctl 하드닝 (수동 적용)

```bash
sudo cp xdr/scripts/99-xdr-hardening.conf /etc/sysctl.d/
sudo sysctl --system
```

---

## 8. 트러블슈팅

### eBPF 프로그램 로드 실패

```bash
# BTF 확인
ls /sys/kernel/btf/vmlinux

# BPF LSM 확인
cat /sys/kernel/security/lsm
# 출력에 "bpf"가 없으면 커널 설정 필요:
# CONFIG_BPF_LSM=y
# CONFIG_LSM="lockdown,yama,apparmor,bpf"

# bpftool 확인
bpftool version
which bpftool    # /usr/sbin/bpftool
```

### XDP 부착 실패

```bash
# 이전 XDP 프로그램 분리
sudo ip link set dev <NIC> xdp off

# NIC 확인
ip link show

# XDP 드라이버 지원 확인 (r8169, igb, i40e, mlx5 등)
ethtool -i <NIC>
```

### 대시보드 접속 불가

```bash
# 포트 확인
ss -tlnp | grep 29992

# 인증서 확인
ls -la /opt/xdr/certs/

# curl 테스트
curl -k https://127.0.0.1:29992/api/health
```

### 이전 BPF 상태 정리

```bash
sudo ip link set dev <NIC> xdp off
sudo rm -rf /sys/fs/bpf/xdr_edr
sudo rm -rf /sys/fs/bpf/xdr_guard
sudo systemctl restart xdr-safe
```

### 로그 확인

```bash
# systemd 로그
sudo journalctl -u xdr-safe -f

# XDR 중요 알림 로그
sudo cat /var/log/xdr/critical/alert_01.log

# XDR 일반 로그
sudo cat /var/log/xdr/general/$(date +%Y-%m-%d).log
```
