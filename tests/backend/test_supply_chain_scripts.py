import hashlib
import io
import os
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _run_bash(command: str, *arguments: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", command, "bash", *(str(argument) for argument in arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def _generate_key_pair(tmp_path: Path, stem: str) -> tuple[Path, Path]:
    private_key = tmp_path / f"{stem}-private.pem"
    public_key = tmp_path / f"{stem}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", private_key],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
        check=True,
        capture_output=True,
    )
    return private_key, public_key


def _write_signed_manifest(directory: Path, private_key: Path) -> None:
    manifest = directory / "manifest.sha256"
    files = sorted(path for path in directory.rglob("*") if path.is_file() and path.name not in {manifest.name, "manifest.sha256.sig"})
    manifest.write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(directory).as_posix()}\n" for path in files),
        encoding="utf-8",
    )
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", directory / "manifest.sha256.sig", manifest],
        check=True,
        capture_output=True,
    )


def test_detached_signature_helpers_reject_tampering(tmp_path: Path) -> None:
    private_key, public_key = _generate_key_pair(tmp_path, "release")
    payload = tmp_path / "release.tar.gz"
    signature = tmp_path / "release.tar.gz.sig"
    payload.write_bytes(b"trusted release")

    signed = _run_bash(
        'source scripts/lib.sh; sign_file "$1" "$2" "$3"; verify_file_signature "$4" "$2" "$3"',
        private_key,
        payload,
        signature,
        public_key,
    )
    assert signed.returncode == 0, signed.stderr

    payload.write_bytes(b"tampered release")
    rejected = _run_bash(
        'source scripts/lib.sh; verify_file_signature "$1" "$2" "$3"',
        public_key,
        payload,
        signature,
    )
    assert rejected.returncode != 0


def test_unsigned_artifacts_require_explicit_opt_in() -> None:
    rejected = _run_bash(
        'unset KODA_ALLOW_UNSIGNED_ARTIFACTS; source scripts/lib.sh; require_unsigned_artifact_opt_in "release"'
    )
    assert rejected.returncode != 0
    assert "KODA_ALLOW_UNSIGNED_ARTIFACTS=1" in rejected.stderr

    allowed = _run_bash(
        'export KODA_ALLOW_UNSIGNED_ARTIFACTS=1; source scripts/lib.sh; require_unsigned_artifact_opt_in "release"'
    )
    assert allowed.returncode == 0
    assert "WARNING" in allowed.stderr


def test_airgap_verifier_rejects_archive_modified_after_signing(tmp_path: Path) -> None:
    private_key, public_key = _generate_key_pair(tmp_path, "release")
    archive = tmp_path / "release.tar.gz"
    signature = tmp_path / "release.tar.gz.sig"
    with tarfile.open(archive, "w:gz") as output:
        member = tarfile.TarInfo("placeholder")
        member.size = 1
        output.addfile(member, io.BytesIO(b"x"))
    subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature, archive],
        check=True,
        capture_output=True,
    )
    with archive.open("ab") as output:
        output.write(b"tampered")

    result = subprocess.run(
        [ROOT / "scripts/verify-airgap-release.sh", archive, "--public-key", public_key, "--signature", signature],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "signature verification failed" in result.stderr


def test_tar_validation_rejects_parent_traversal_and_unsafe_links(tmp_path: Path) -> None:
    traversal = tmp_path / "traversal.tar.gz"
    with tarfile.open(traversal, "w:gz") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))

    unsafe_link = tmp_path / "unsafe-link.tar.gz"
    with tarfile.open(unsafe_link, "w:gz") as archive:
        member = tarfile.TarInfo("safe-name")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)

    for archive in (traversal, unsafe_link):
        result = _run_bash('source scripts/lib.sh; validate_tar_archive "$1"', archive)
        assert result.returncode != 0
        assert "unsafe archive" in result.stderr


def test_airgap_release_is_verified_with_external_key_before_extraction() -> None:
    builder = (ROOT / "scripts/build-airgap-release.sh").read_text()
    verifier = (ROOT / "scripts/verify-airgap-release.sh").read_text()
    installer = (ROOT / "scripts/install-airgap.sh").read_text()

    assert 'KODA_RELEASE_SIGNING_KEY' in builder
    assert 'require_unsigned_artifact_opt_in' in builder
    assert 'sign_file "$signing_key" "$output" "${output}.sig"' in builder
    assert '--public-key' in verifier
    assert 'require_unsigned_artifact_opt_in' in verifier
    assert verifier.index("verify_file_signature") < verifier.index("validate_tar_archive")
    assert verifier.index("verify_file_signature") < verifier.index('tar -xzf "$input"')
    assert '--public-key' in installer
    assert 'KODA_ALLOW_UNSIGNED_ARTIFACTS' in installer
    assert 'chmod 700 "$tmp"' in installer
    assert 'verify-airgap-release.sh" "$staged_archive"' in installer
    assert installer.index('verify-airgap-release.sh" "$staged_archive"') < installer.index('tar -xzf "$staged_archive"')


def test_backup_manifest_is_signed_and_restore_uses_verified_staging() -> None:
    backup = (ROOT / "scripts/backup-system.sh").read_text()
    verifier = (ROOT / "scripts/verify-backup.sh").read_text()
    restore = (ROOT / "scripts/restore-system.sh").read_text()

    assert 'KODA_BACKUP_SIGNING_KEY' in backup
    assert 'require_unsigned_artifact_opt_in' in backup
    assert 'sign_file "$signing_key" "${backup_dir}/manifest.sha256" "${backup_dir}/manifest.sha256.sig"' in backup
    assert '--public-key' in verifier
    assert 'require_unsigned_artifact_opt_in' in verifier
    assert verifier.index("verify_file_signature") < verifier.index("verify_manifest")
    assert "validate_backup_metadata" in verifier
    assert "validate_tar_archive" in verifier
    assert '--public-key' in restore
    assert 'KODA_ALLOW_UNSIGNED_ARTIFACTS' in restore
    assert 'chmod 700 "$staging_root"' in restore
    assert 'verify-backup.sh" "$staged_backup"' in restore
    assert restore.index('verify-backup.sh" "$staged_backup"') < restore.index("compose down")
    assert 'alpine_untar "${staged_backup}/tracker-artifacts.tar.gz"' in restore


def test_backup_verifier_checks_signed_metadata_and_tar_paths(tmp_path: Path) -> None:
    private_key, public_key = _generate_key_pair(tmp_path, "backup")
    backup = tmp_path / "backup"
    payload = tmp_path / "payload"
    backup.mkdir()
    payload.mkdir()
    (payload / "item").write_text("artifact", encoding="utf-8")
    env_file = tmp_path / "test.env"
    values = {
        "COMPOSE_PROJECT_NAME": "test-project",
        "TRACKER_DB_NAME": "tracker",
        "TRACKER_ARTIFACTS_VOLUME_NAME": "test_tracker_artifacts",
        "VULN_DATA_VOLUME_NAME": "test_vuln_data",
    }
    env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    (backup / "metadata.env").write_text(
        "BACKUP_CREATED_AT=20261001T010203Z\n" + "".join(f"{key}={value}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    (backup / "postgres-globals.sql").write_text("sql", encoding="utf-8")
    (backup / "tracker.dump").write_bytes(b"dump")
    for name in ("tracker-artifacts", "vuln-data"):
        with tarfile.open(backup / f"{name}.tar.gz", "w:gz") as archive:
            archive.add(payload / "item", arcname="item")
    _write_signed_manifest(backup, private_key)
    environment = {**os.environ, "ENV_FILE": str(env_file)}

    verified = subprocess.run(
        [ROOT / "scripts/verify-backup.sh", backup, "--public-key", public_key],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr

    (backup / "manifest.sha256.sig").unlink()
    unsigned_rejected = subprocess.run(
        [ROOT / "scripts/verify-backup.sh", backup],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert unsigned_rejected.returncode != 0
    assert "KODA_ALLOW_UNSIGNED_ARTIFACTS=1" in unsigned_rejected.stderr

    unsigned_allowed = subprocess.run(
        [ROOT / "scripts/verify-backup.sh", backup],
        cwd=ROOT,
        env={**environment, "KODA_ALLOW_UNSIGNED_ARTIFACTS": "1"},
        capture_output=True,
        text=True,
    )
    assert unsigned_allowed.returncode == 0, unsigned_allowed.stderr
    assert "WARNING: accepting unsigned backup" in unsigned_allowed.stderr

    metadata = (backup / "metadata.env").read_text(encoding="utf-8")
    (backup / "metadata.env").write_text(metadata.replace("COMPOSE_PROJECT_NAME=test-project", "COMPOSE_PROJECT_NAME=other"), encoding="utf-8")
    _write_signed_manifest(backup, private_key)
    rejected = subprocess.run(
        [ROOT / "scripts/verify-backup.sh", backup, "--public-key", public_key],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "metadata mismatch" in rejected.stderr


def test_directory_offline_bundle_requires_signature_exact_inventory_and_private_staging(tmp_path: Path) -> None:
    builder = (ROOT / "scripts/build-offline-bundle.sh").read_text()
    verifier = (ROOT / "scripts/verify-offline-bundle.sh").read_text()
    importer = (ROOT / "scripts/import-offline-bundle.sh").read_text()

    assert "KODA_RELEASE_SIGNING_KEY" in builder
    assert "require_unsigned_artifact_opt_in" in builder
    assert 'sign_file "$signing_key" "${bundle_dir}/manifest.sha256"' in builder
    assert "verify_file_signature" in verifier
    assert "require_unsigned_artifact_opt_in" in verifier
    assert verifier.index("verify_file_signature") < verifier.index("verify_manifest")
    assert "validate_manifest_inventory" in verifier
    assert 'chmod 700 "$staging_root"' in importer
    assert "KODA_ALLOW_UNSIGNED_ARTIFACTS" in importer
    assert 'verify-offline-bundle.sh" "$staged_bundle"' in importer
    assert importer.index('verify-offline-bundle.sh" "$staged_bundle"') < importer.index("docker load")

    private_key, _ = _generate_key_pair(tmp_path, "directory-bundle")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "trusted").write_text("trusted", encoding="utf-8")
    _write_signed_manifest(bundle, private_key)
    (bundle / "unlisted.tar").write_text("attacker-added", encoding="utf-8")
    rejected = _run_bash(
        'source scripts/lib.sh; validate_manifest_inventory "$1/manifest.sha256" "$1"',
        bundle,
    )
    assert rejected.returncode != 0
    assert "inventory mismatch" in rejected.stderr
