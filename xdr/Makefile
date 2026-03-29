.PHONY: test lint build-ebpf build-dashboard install all clean help

# ═══════════════════════════════════════════════════════
# XDR Build System
# ═══════════════════════════════════════════════════════

help: ## 도움말 표시
	@grep -E '^[a-z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk -F':.*## ' '{printf "  \033[1;36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Testing ──────────────────────────────────────────

test: ## pytest 전체 테스트 실행
	cd xdr-core && python -m pytest tests/ -v --tb=short

test-cov: ## pytest + 커버리지 리포트
	cd xdr-core && python -m pytest tests/ -v --cov=. --cov-report=term-missing

test-quick: ## pytest 빠른 실행 (출력 최소)
	cd xdr-core && python -m pytest tests/ -q --tb=line

# ── Linting ──────────────────────────────────────────

lint: ## 코드 스타일 검사 (flake8)
	cd xdr-core && python -m flake8 --max-line-length=120 --ignore=E501,W503 \
		*.py api/ engine/ edr_detector/

# ── Build ────────────────────────────────────────────

build-ebpf: ## eBPF 프로그램 빌드 (EDR + NDR)
	cd ebpf-edr && make
	cd xdp-ndr && make

build-dashboard: ## React 대시보드 빌드
	cd dashboard && npm ci && npm run build

build: build-ebpf build-dashboard ## 전체 빌드

# ── Install ──────────────────────────────────────────

install: build ## 빌드 + /opt/xdr 설치
	@./scripts/install.sh

# ── Clean ────────────────────────────────────────────

clean: ## 빌드 아티팩트 정리
	cd ebpf-edr && make clean 2>/dev/null || true
	cd xdp-ndr && make clean 2>/dev/null || true
	rm -rf dashboard/dist dashboard/node_modules
	find xdr-core -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find xdr-core -name '*.pyc' -delete 2>/dev/null || true

# ── All ──────────────────────────────────────────────

all: test lint build ## 테스트 + 린트 + 빌드
