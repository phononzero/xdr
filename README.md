# 🛡️ XDR — eBPF 기반 Linux 통합 보안 플랫폼 [TEST VERSION v0.1]

**eXtended Detection & Response** — eBPF EDR + XDP NDR을 단일 커널 레벨 엔진으로 통합한 Linux 보안 솔루션.

---

## 아키텍처

```
┌──────────────────────────────────────────────────┐
│              XDR Dashboard (React+TS)            │
│           https://127.0.0.1:29992                │
└──────────────────────┬───────────────────────────┘
                       │ JWT Auth + SSE Stream
┌──────────────────────▼───────────────────────────┐
│            Flask REST API (11 Routes)            │
│  auth │ middleware │ routes_* │ spa               │
└──────┬──────────┬──────────┬─────────────────────┘
       │          │          │
 ┌─────▼────┐ ┌───▼───┐ ┌───▼──────────┐
 │ EDR      │ │  NDR  │ │ Correlation  │
 │ Detector │ │  XDP  │ │   Engine     │
 │ (eBPF)   │ │(eBPF) │ │              │
 └────┬─────┘ └───┬───┘ └──────────────┘
      │           │
 ┌────▼───────────▼────┐
 │  Linux Kernel 6.x   │
 │  BPF LSM + kprobes  │
 │  XDP + Ring Buffers  │
 └─────────────────────┘
```

## 주요 기능

### EDR (Endpoint Detection & Response)
| 기능 | eBPF Hook | MITRE ATT&CK |
|------|-----------|:---:|
| 프로세스 실행 감시 + argv 캡처 | `tracepoint/sched_process_exec` | T1059 |
| TCP 아웃바운드 연결 감지 | `kprobe/tcp_connect` | T1071 |
| 파일 접근 모니터링 (FIM) | `lsm/file_open` | T1005 |
| 커널 모듈 로드 감시 | `lsm/kernel_module_request` | T1547.006 |
| 권한 상승 감지 | `lsm/bprm_check_security` | T1548 |
| 파일리스 악성코드 (memfd_create) | `tracepoint/syscalls/sys_enter_memfd_create` | T1620 |
| 프로세스 인젝션 (ptrace) | `tracepoint/syscalls/sys_enter_ptrace` | T1055.008 |
| 커널 모듈 로딩 (init_module) | `tracepoint/syscalls/sys_enter_init_module` | T1547.006 |
| 프로세스 계보 추적 + 공격 체인 | `tracepoint/sched_process_exit` | — |

### NDR (Network Detection & Response)
| 기능 | 동작 |
|------|------|
| IP 블랙리스트 | XDP 하드웨어 레벨 패킷 DROP |
| 포트 블랙리스트 | XDP 패킷 DROP |
| ARP 스푸핑 탐지 | MAC-IP 바인딩 검증 → DROP |
| DNS 터널링 의심 | 대형 DNS 패킷 경고 |

### 상관분석 & 탐지 모듈
- **LOLBins 탐지** — 80+ 규칙, 450+ 패턴
- **YARA 스캐너** — 커스텀 규칙 기반 정적 분석
- **APT Kill Chain 상관분석** — 7개 공격 시나리오
- **DNS 모니터** — DGA 도메인 탐지, DNS 터널링
- **TLS 핑거프린트** — JA3 해시 분석
- **SSL 평문 감시** — OpenSSL/GnuTLS uprobe
- **파일 무결성 모니터** — SHA256 기준선 비교
- **메모리 포렌식 스캐너** — RWX 영역, 삭제된 매핑 탐지
- **위협 인텔리전스** — 외부 IOC 피드 자동 업데이트
- **프로세스 계보** — 실시간 프로세스 트리 + 7개 공격 체인 패턴

---

## 시스템 요구사항

| 요구사항 | 버전 |
|---------|------|
| Linux Kernel | 6.1+ (BPF LSM, BTF 활성화 필수) |
| Python | 3.11+ |
| libbpf | 1.0+ |
| clang/llvm | 14+ (eBPF 빌드) |
| bpftool | 커널 버전 매칭 |
| Node.js | 18+ (대시보드 빌드, 선택) |

### 필수 커널 설정
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_LSM="lockdown,yama,apparmor,bpf"
```
> 전체 커널 설정 프래그먼트: [`kernel/kernel.config`](kernel/kernel.config)

---

## Quick Start

```bash
# 1. 의존성 설치 (Debian/Ubuntu)
sudo apt install clang llvm bpftool libbpf-dev \
     python3 python3-venv python3-pip

# 2. vmlinux.h 생성
bpftool btf dump file /sys/kernel/btf/vmlinux format c > xdr/ebpf-edr/vmlinux.h
cp xdr/ebpf-edr/vmlinux.h xdr/xdp-ndr/vmlinux.h
cp xdr/ebpf-edr/vmlinux.h xdr/xdr-core/vmlinux.h

# 3. eBPF 프로그램 빌드
bash scripts/build-ebpf.sh

# 4. 대시보드 빌드 (선택)
cd xdr/dashboard && npm ci && npm run build && cd ../..

# 5. XDR 설치
sudo bash xdr/scripts/install_safe.sh

# 6. 실행
sudo python3 /opt/xdr/xdr-core/xdr_safe_mode.py

# 또는 systemd 서비스로:
sudo systemctl start xdr-safe
sudo systemctl enable xdr-safe
```

> 상세 설치 가이드: [INSTALL.md](INSTALL.md)

---

## 프로젝트 구조

```
xdr/
├── kernel/               # 커스텀 커널 설정 프래그먼트
│   └── kernel.config
├── scripts/              # 빌드 스크립트
│   └── build-ebpf.sh
├── xdr/
│   ├── ebpf-edr/         # eBPF EDR 프로그램 (C)
│   │   ├── edr.bpf.c     # 10개 커널 훅
│   │   └── bpf_guard.bpf.c
│   ├── xdp-ndr/          # XDP NDR 프로그램 (C)
│   │   └── ndr.bpf.c     # XDP 패킷 필터
│   ├── xdr-core/         # Python 코어 엔진
│   │   ├── xdr_engine.py       # 메인 엔진
│   │   ├── xdr_safe_mode.py    # Safe Mode 런처
│   │   ├── config_loader.py    # 통합 설정 로더
│   │   ├── xdr_config.yaml     # 설정 파일
│   │   ├── api/                # Flask REST API (11 routes)
│   │   ├── engine/             # 상관분석, 링버퍼, 로깅
│   │   ├── edr_detector/       # 탐지 규칙 엔진
│   │   │   └── detectors/      # 11개 전문 탐지 모듈
│   │   └── tests/              # pytest 테스트
│   ├── dashboard/        # React + TypeScript 대시보드
│   ├── apparmor/         # AppArmor 프로파일
│   └── scripts/          # 설치 스크립트
│       ├── install_safe.sh
│       └── 99-xdr-hardening.conf
├── .gitignore
├── README.md
├── INSTALL.md
└── LICENSE
```

## API 인증

```bash
# JWT 토큰 획득
curl -k https://127.0.0.1:29992/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"secret": "<API_SECRET>"}'

# API 호출
curl -k https://127.0.0.1:29992/api/status \
  -H "Authorization: Bearer <TOKEN>"
```

## 주요 API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/api/auth/login` | JWT 토큰 발급 |
| `GET` | `/api/status` | EDR/NDR 상태 |
| `GET` | `/api/health` | 모듈 건강 상태 |
| `GET` | `/api/events` | 이벤트 히스토리 |
| `GET` | `/api/stream` | SSE 실시간 스트림 |
| `GET` | `/api/blocklists` | 차단 목록 |
| `POST` | `/api/blocklists/ip` | IP 차단 추가 |
| `GET` | `/api/processes` | 프로세스 목록 |
| `GET` | `/api/connections` | 네트워크 연결 |
| `GET` | `/api/integrity/status` | 무결성 상태 |

## 테스트

```bash
cd xdr
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cd xdr-core
python -m pytest tests/ -v --tb=short
```

## 라이선스

GPL-3.0 — eBPF 프로그램이 GPL 라이선스를 요구합니다.
