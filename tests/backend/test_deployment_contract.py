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
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track" in (ROOT / ".env.example").read_text()
    assert "DTRACK_API_BASE_URL=http://localhost:8088/dependency-track/api" not in (ROOT / ".env.example").read_text()
    assert "location = /dependency-track { return 308 /dependency-track/; }" in gateway
    assert gateway.count("client_max_body_size 25m;") == 1
    assert all("AIRGAP_HEALTH_TIMEOUT:-420" in launcher for launcher in launchers)


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
