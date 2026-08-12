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
    assert "location = /dependency-track { return 308 /dependency-track/; }" in gateway
    assert all("AIRGAP_HEALTH_TIMEOUT:-420" in launcher for launcher in launchers)
