SHELL := /bin/bash
.DEFAULT_GOAL := help

help:
	@printf "Targets:\n"
	@printf "  make env                 # .env.example을 .env로 복사\n"
	@printf "  make config              # docker compose 설정 렌더링\n"
	@printf "  make build               # portal 이미지 빌드\n"
	@printf "  make up                  # 전체 스택 기동\n"
	@printf "  make down                # 전체 스택 중지\n"
	@printf "  make logs                # gateway 로그 확인\n"
	@printf "  make bundle              # 오프라인 번들 생성\n"
	@printf "  make verify-bundle       # 오프라인 번들 검증\n"
	@printf "  make backup              # 논리 백업 생성\n"
	@printf "  make verify-backup       # 백업 검증\n"
	@printf "  make restore BACKUP=...  # 백업 복원\n"
	@printf "  make import-vuln BUNDLE=...     # 취약점 데이터 반입\n"
	@printf "  make rollback-vuln               # 취약점 데이터 롤백\n"
	@printf "  make verify-dtrack               # Dependency-Track 키·권한 검증\n"
	@printf "  scripts/build-vuln-bundle.sh ...  # NVD/KEV/Grype bundle 생성\n"
	@printf "  포털 취약점 데이터 화면에서 반입 상태 동기화       # DB/audit 등록\n"
	@printf "  scripts/upload-sbom.sh ...        # KODA/CI용 SBOM 업로드\n"

env:
	@test -f .env || cp .env.example .env

config:
	docker compose --env-file .env.example config

build:
	docker compose --env-file .env.example build portal-web portal-api portal-worker

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f gateway

bundle:
	./scripts/build-offline-bundle.sh

verify-bundle:
	./scripts/verify-offline-bundle.sh "$(BUNDLE)"

backup:
	./scripts/backup-system.sh

verify-backup:
	./scripts/verify-backup.sh "$(BACKUP)"

restore:
	./scripts/restore-system.sh "$(BACKUP)"

import-vuln:
	./scripts/import-vuln-bundle.sh "$(BUNDLE)"

rollback-vuln:
	./scripts/rollback-vuln-bundle.sh

verify-dtrack:
	./scripts/verify-dtrack-connection.sh
