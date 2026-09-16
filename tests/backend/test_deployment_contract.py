from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dependency_track_is_part_of_linux_readiness() -> None:
    compose = (ROOT / "compose.yaml").read_text()
    gateway = (ROOT / "deploy/nginx/gateway.conf.template").read_text()
    launchers = [
        (ROOT / "scripts/start-airgap.sh").read_text(),
        (ROOT / "scripts/install-airgap.sh").read_text(),
    ]

    assert "dtrack-frontend:\n        condition: service_healthy" in compose
    assert compose.count("dtrack-apiserver:\n        condition: service_healthy") == 2
    assert "http://127.0.0.1:9000/health/ready" in compose
    assert "http://127.0.0.1:8080/dependency-track/" in compose
    assert "http://127.0.0.1:8080/dependency-track/api/version" in compose
    assert "API_BASE_URL: ${DTRACK_API_BASE_URL:-http://localhost:8088/dependency-track}" in compose
    assert "BASE_PATH: ${DTRACK_BASE_PATH:-/dependency-track}/" in compose
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track" in (ROOT / ".env.example").read_text()
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track/api" not in (ROOT / ".env.example").read_text()
    assert "location = /dependency-track { return 308 /dependency-track/; }" in gateway
    assert "proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}/;" in gateway
    assert "proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}${DTRACK_BASE_PATH}/;" not in gateway
    assert "location = /dependency-track/static/config.json" in gateway
    assert 'add_header Cache-Control "no-store" always;' in gateway
    assert gateway.count("client_max_body_size 501m;") == 1
    assert "UPLOAD_MAX_BYTES=524288000" in (ROOT / ".env.example").read_text()
    assert all("AIRGAP_HEALTH_TIMEOUT:-420" in launcher for launcher in launchers)


def test_upload_limit_defaults_match_gateway_and_ui() -> None:
    config = (ROOT / "apps/api/koda_tracker/config.py").read_text()
    ui = (ROOT / "apps/web/src/App.tsx").read_text()

    assert "max_upload_bytes: int = 500 * 1024 * 1024" in config
    assert 'standaloneMode ? "100 MiB" : "500 MiB"' in ui
    assert "client_max_body_size 501m;" in (ROOT / "deploy/nginx/gateway.conf.template").read_text()


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
