# 업데이트 내역 (UPDATE.md)

XDR 프로젝트의 주요 변경 이력입니다. 최신 항목이 위에 옵니다.

---

## v0.2 — 탐지 파이프라인 완성 및 미완성 기능 구현 (2026-07-02)

기존에 **탐지되지 않던 침해 사고**를 실제로 탐지하도록 전면 감사 후 버그를
수정하고, 죽어 있던(구현됐으나 미연결/미동작) 기능을 모두 완성했습니다.
모든 항목은 실제 커널 eBPF에 대해 E2E로 검증했습니다. (테스트 147개 전부 통과)

### 🐛 탐지를 막던 버그 수정

- **민감 파일(FIM) 탐지 복구** — `EVT_FILE_OPEN` 상수가 엔진에 임포트되지 않아
  파일 접근 이벤트마다 `NameError`가 debug 로그에 묻혀 탐지가 죽어 있었음. 임포트
  추가 + 파이프라인 예외를 ERROR 레벨로 승격(조용한 실패 방지).
- **APT 킬체인 상관분석 복구** — 탐지기 결과(`reason`/`mitre_id`)가 상관 엔진에
  전달되지 않아 시나리오 3·5·7(권한상승→C2, 지속성→리버스셸, LOLBin 연쇄)이 실제
  이벤트로는 절대 트리거되지 않았음. 이벤트 병합으로 복구.
- **IP 바이트 순서 버그** — eBPF의 네트워크 순서 주소를 빅엔디안으로 변환해
  `203.0.113.5`가 `5.113.0.203`으로 뒤집혀 **위협 인텔리전스 IP 매칭이 무력화**
  됐음. 6개 변환 지점을 네이티브 패킹으로 통일.
- **권한 상승 탐지 정상화** — LSM `bprm_check` 훅이 모든 exec마다 발생(노이즈)했고,
  이 커널에선 훅 시점에 setuid euid가 아직 적용 전이라 무의미. **파일 inode의
  setuid 비트 + root 소유자**를 검사하도록 재작성(su/sudo/passwd 등 실제 상승만 탐지).
- **beacon/측면이동 IP 타입** — 정수 `dst_ip`가 문자열 검사 로직에 전달돼 dedup
  키·localhost 필터가 오작동. 점표기 문자열로 정규화.

### ✨ 미완성 기능 구현 (구현됐으나 동작하지 않던 기능)

- **루트킷/커널 무결성 주기 스캔** — 숨은 프로세스·삭제된 바이너리·sysctl 변조
  탐지가 스케줄되지 않아 미실행이었음 → 120초 주기 스캔 스레드로 배선.
- **측면이동 탐지** — NET_CONNECT 경로에 배선(내부 포트스캔/SSH/SMB).
- **SSL 평문 캡처** — `ssl_probe`가 tracefs 메타데이터만 읽어 평문 내용 탐지가
  죽어 있었음. libbpf로 `ssl_probe.bpf.o`를 로드해 uprobe(`SSL_write`/`SSL_read`
  및 **`SSL_write_ex`/`SSL_read_ex`** + GnuTLS)를 부착하고 `ssl_events` 링버퍼에서
  실제 평문을 읽어 탐지. (CPython은 `SSL_write_ex`를 호출하므로 `_ex` 훅 필수)
- **TLS JA3 핑거프린트** — 패킷 입력이 없어 항상 빈 결과였음. AF_PACKET 원시 소켓
  스니퍼(cBPF로 TCP만 필터)로 ClientHello를 캡처해 JA3 계산 → 악성 JA3 DB 매칭.
- **AssetScanner** — 기동 호출부가 없어 `/api/assets/scan/*`가 무동작이었음.
  엔진이 300초 주기로 기동하도록 배선.
- **`xdr_config.yaml` 전 섹션 반영** — `engine`/`correlation`만 소비되고 나머지는
  하드코딩 값이 우선이라 무효였음. cache/dns/integrity/threat_intel/self_protect/
  tls/logging 전부 실제 코드에 배선(`XDR_<SECTION>_<KEY>` 환경변수 오버라이드 유효).

### 🆕 신규 탐지 기능

- **컨테이너 탈출 탐지** — eBPF가 필요한 필드(`syscall`/`ns_type`)를 방출하지 않아
  탐지기가 도달 불가였음.
  - `sys_enter_setns`/`sys_enter_unshare` tracepoint 추가 →
    `EVT_CONTAINER_ESCAPE`(9) 신규 이벤트 타입(네임스페이스 조작 탐지).
  - `lsm/file_open`을 `bpf_d_path`로 **전체 경로** 캡처(기존 leaf 이름 →) →
    docker.sock / cgroup release_agent / `/proc/1/root` 벡터 탐지. 부수적으로
    이전엔 깨져 있던 민감 **디렉토리** 매칭(`/etc/ssh/` 등)도 복구됨.
  - `_is_containerized`로 컨테이너 내부 프로세스만 알림(호스트 오탐 없음).

### 🔧 자기보호(BPF Guard) 정상화

- `load()`가 무효 attach 타입(`prog attach ... lsm`)을 사용해 실패했고 맵도
  pin되지 않아 전체가 동작 불가였음 → `loadall ... autoattach pinmaps`로 수정.
- `register_pid` hex 인코딩 버그 수정(낱글자 → 바이트 토큰).
- `get_stats`/`get_denied_events`를 **in-process bpf() syscall**로 구현 — enforcing
  중에는 XDR의 bpftool 서브프로세스(별도 PID)가 차단되지만, 등록된 XDR 프로세스는
  pinned 맵을 직접 읽을 수 있음(allowed/denied 카운트 + 차단 이벤트 링버퍼).

### 📦 빌드/의존성

- `scripts/build-ebpf.sh`가 `bpf_guard.bpf.o`, `ssl_probe.bpf.o`도 빌드·설치.
- `yara-python>=4.5`를 `requirements.txt`에 추가(휠에 libyara 번들, 시스템 의존성
  불필요). YARA 스캐너가 실제 규칙 컴파일+스캔 동작(미설치 시 graceful degrade).
- 오래된 API 테스트 4건 수정(HMAC 인증 헤더 누락, 라우트 경로 갱신).
- `yara_scanner.py` 정규식 raw string 처리(SyntaxWarning 제거).

### ✅ E2E 검증된 탐지 능력

프로세스 exec/LOLBin(124 규칙) · memfd_create(파일리스) · ptrace(인젝션) ·
C2C beacon · 민감 파일 FIM · setuid 권한상승 · 커널 모듈 로딩 · 루트킷/커널 무결성 ·
SSL 평문 내용 · TLS JA3 · 컨테이너 탈출(setns/unshare + 파일 벡터) · APT 킬체인
상관분석 · XDP NDR 차단 — 모두 실제 커널에서 탐지 확인.

---

## v0.1 — TEST VERSION (초기)

eBPF EDR + XDP NDR 통합 초기 버전. 아키텍처/모듈 골격, 대시보드, API, 탐지 규칙
엔진의 최초 구현.
