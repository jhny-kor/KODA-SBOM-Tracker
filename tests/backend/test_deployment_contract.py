import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dependency_track_is_optional_in_linux_readiness() -> None:
    compose = (ROOT / "compose.yaml").read_text()
    gateway = (ROOT / "deploy/nginx/gateway.conf.template").read_text()
    launchers = [
        (ROOT / "scripts/start-airgap.sh").read_text(),
        (ROOT / "scripts/install-airgap.sh").read_text(),
    ]

    assert "dtrack-frontend:\n        condition: service_healthy" not in compose
    assert compose.count("dtrack-apiserver:\n        condition: service_healthy") == 1
    assert compose.count("profiles: [dependency-track]") == 2
    assert "http://127.0.0.1:9000/health/ready" in compose
    assert "http://127.0.0.1:8080/dependency-track/" not in compose
    assert "http://127.0.0.1:8080/dependency-track/api/version" not in compose
    assert "API_BASE_URL: ${DTRACK_API_BASE_URL:-http://localhost:8088/dependency-track}" in compose
    assert "BASE_PATH: ${DTRACK_BASE_PATH:-/dependency-track}/" in compose
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track" in (ROOT / ".env.example").read_text()
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track/api" not in (ROOT / ".env.example").read_text()
    assert "location = /dependency-track {" in gateway
    assert "if ($dtrack_disabled) { return 404; }" in gateway
    assert "proxy_pass http://$dtrack_web;" in gateway
    assert "resolver 127.0.0.11" in gateway
    assert "proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}${DTRACK_BASE_PATH}/;" not in gateway
    assert "location = /dependency-track/static/config.json" in gateway
    assert 'add_header Cache-Control "no-store" always;' in gateway
    assert "client_max_body_size 64k;" in gateway
    assert "location = /api/v1/sbom-runs" in gateway
    assert "client_max_body_size 501m;" in gateway
    assert "limit_conn sbom_upload_conn 2;" in gateway
    assert "UPLOAD_MAX_BYTES=524288000" in (ROOT / ".env.example").read_text()
    assert '${PUBLIC_HTTP_BIND:-127.0.0.1}:${PUBLIC_HTTP_PORT:-8088}:8080' in compose
    assert "TRACKER_PUBLIC_BIND: ${PUBLIC_HTTP_BIND:-127.0.0.1}" in compose
    assert all("AIRGAP_HEALTH_TIMEOUT:-420" in launcher for launcher in launchers)


def test_upload_limit_defaults_match_gateway_and_ui() -> None:
    config = (ROOT / "apps/api/koda_tracker/config.py").read_text()
    ui = (ROOT / "apps/web/src/App.tsx").read_text()

    assert "max_upload_bytes: int = 500 * 1024 * 1024" in config
    assert 'standaloneMode ? "100 MiB" : "500 MiB"' in ui
    assert "client_max_body_size 501m;" in (ROOT / "deploy/nginx/gateway.conf.template").read_text()


def test_bootstrap_example_is_not_a_known_credential_and_local_init_generates_secrets() -> None:
    example = (ROOT / ".env.example").read_text()
    initializer = (ROOT / "scripts/init-local-env.sh").read_text()

    assert "TRACKER_BOOTSTRAP_ADMIN_PASSWORD=\n" in example
    assert "change-me-admin-password" not in example
    assert "openssl rand" in initializer
    assert "TRACKER_BOOTSTRAP_ADMIN_PASSWORD" in initializer


def test_remote_bind_preflight_requires_https_and_secure_cookies() -> None:
    preflight = (ROOT / "scripts/preflight-airgap.sh").read_text()

    assert "PUBLIC_HTTP_BIND" in preflight
    assert "TRACKER_ENVIRONMENT" in preflight
    assert "TRACKER_SECURE_COOKIES" in preflight
    assert "TRACKER_PUBLIC_ORIGIN" in preflight


def test_airgap_preflight_rejects_remote_http_but_allows_local_http_and_remote_https(tmp_path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    base = {
        "POSTGRES_PASSWORD": "strong-postgres-password",
        "DTRACK_DB_PASSWORD": "strong-dtrack-password",
        "TRACKER_DB_USER": "sbom_tracker",
        "TRACKER_DB_NAME": "sbom_tracker",
        "TRACKER_DB_PASSWORD": "strong-tracker-password",
        "TRACKER_DATABASE_URL": "postgresql+psycopg://sbom_tracker:strong-tracker-password@postgres:5432/sbom_tracker",
        "TRACKER_BOOTSTRAP_ADMIN_PASSWORD": "strong-bootstrap-password",
        "TRACKER_DEPENDENCY_TRACK_API_KEY": "strong-api-key",
        "DTRACK_API_BASE_URL": "https://tracker.example/dependency-track",
    }
    environment = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}

    def run(**updates: str) -> subprocess.CompletedProcess[str]:
        values = base | updates
        env_file = tmp_path / f"case-{len(list(tmp_path.glob('case-*')))}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        return subprocess.run(
            [ROOT / "scripts/preflight-airgap.sh", env_file],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
        )

    local = run(
        PUBLIC_HTTP_BIND="127.0.0.1",
        TRACKER_ENVIRONMENT="development",
        TRACKER_SECURE_COOKIES="false",
        TRACKER_PUBLIC_ORIGIN="http://127.0.0.1:8088",
    )
    assert local.returncode == 0, local.stderr

    remote_http = run(
        PUBLIC_HTTP_BIND="0.0.0.0",
        TRACKER_ENVIRONMENT="development",
        TRACKER_SECURE_COOKIES="false",
        TRACKER_PUBLIC_ORIGIN="http://tracker.example",
    )
    assert remote_http.returncode != 0

    remote_https = run(
        PUBLIC_HTTP_BIND="0.0.0.0",
        TRACKER_ENVIRONMENT="production",
        TRACKER_SECURE_COOKIES="true",
        TRACKER_PUBLIC_ORIGIN="https://tracker.example",
    )
    assert remote_https.returncode == 0, remote_https.stderr


def test_airgap_installer_retags_manifest_verified_remote_images() -> None:
    installer = (ROOT / "scripts/install-airgap.sh").read_text()

    assert '[[ "$env_file" == "$install_dir/.env" ]] || cp' in installer
    assert "declare -A loaded_ids" in installer
    assert 'runtime_ref="${image_ref%@*}"' in installer
    assert 'docker tag "$image_id" "$runtime_ref"' in installer
    assert 'done < "$install_dir/config/images.lock"' in installer
    assert "--no-build --pull never" in installer


def test_maintenance_scripts_use_the_installed_compose_file() -> None:
    library = (ROOT / "scripts/lib.sh").read_text()

    assert '--project-directory "$ROOT_DIR"' in library
    assert '-f "$ROOT_DIR/compose.yaml"' in library


def test_dtrack_provisioner_accepts_unchanged_permissions() -> None:
    provisioner = (ROOT / "scripts/configure-dtrack-key.sh").read_text()
    verifier = (ROOT / "scripts/verify-dtrack-connection.sh").read_text()

    assert 'exc.code == 304 and method == "PUT" and path == "v1/permission/team"' in provisioner
    assert 'get("v1/user/self/permissions")' not in verifier
    assert 'team.get("permissions", [])' in verifier
