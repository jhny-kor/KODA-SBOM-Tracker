import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_distribution_paths_keep_required_license_material() -> None:
    assert "Apache License" in read("LICENSE")
    assert "CycloneDX community" in read("NOTICE")
    assert "internal-only" in read("THIRD_PARTY_NOTICES.md")

    package = json.loads(read("apps/web/package.json"))
    assert package["license"] == "Apache-2.0"
    package_lock = json.loads(read("apps/web/package-lock.json"))
    assert package_lock["packages"][""]["license"] == "Apache-2.0"
    assert 'license = "Apache-2.0"' in read("apps/api/pyproject.toml")

    web_dockerfile = read("apps/web/Dockerfile")
    assert "node_modules/react/LICENSE" in web_dockerfile
    assert "node_modules/scheduler/LICENSE" in web_dockerfile
    assert "node_modules/vite/LICENSE.md" in web_dockerfile
    assert "node_modules/pretendard/dist/LICENSE.txt" in web_dockerfile
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md" in web_dockerfile
    assert "COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md" in read("apps/api/Dockerfile")

    preview_builder = read("scripts/build-windows-preview-installer.ps1")
    assert '"Pretendard-OFL-1.1.txt"' in preview_builder
    assert '"Scheduler-MIT.txt"' in preview_builder
    assert '"Vite-MIT-and-third-party.txt"' in preview_builder
    assert "LicenseFile={#StageDir}\\legal\\LICENSE" in read("installer/koda-sbom-tracker-preview.iss")

    for script in ("scripts/build-airgap-release.sh", "scripts/build-offline-bundle.sh"):
        content = read(script)
        assert "KODA_DISTRIBUTION_SCOPE" in content
        assert "DISTRIBUTION_SCOPE=internal-only" in content

    assert 'ValidateSet("Internal", "External")' in read("scripts/build-windows-installer.ps1")
