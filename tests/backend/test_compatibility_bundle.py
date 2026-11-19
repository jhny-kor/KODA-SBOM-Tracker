from copy import deepcopy
import hashlib
from io import BytesIO
import json
import tarfile
from zipfile import ZipFile

from fastapi.testclient import TestClient
import pytest

from koda_tracker.compatibility_bundle import parse_compatibility_bundle
from koda_tracker.compatibility_data import matching_references
from koda_tracker import db as db_module
from koda_tracker.main import app
from test_compatibility_rpm import _rpm
from test_suite_integrations import _login, _service, isolated_tracker  # noqa: F401


def descriptor(kind, path, url, raw):
    return {"kind": kind, "path": path, "url": url, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}


def example():
    pom = b'<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>x.example</groupId><artifactId>a</artifactId><version>2.1</version><properties><maven.compiler.release>11</maven.compiler.release></properties></project>'
    wheel_io = BytesIO()
    filename = "sample-2.1-py3-none-any.whl"
    with ZipFile(wheel_io, "w") as wheel:
        wheel.writestr("sample-2.1.dist-info/METADATA", "Name: sample\nVersion: 2.1\nRequires-Python: >=3.10\nRequires-Dist: base>=1\n\n")
        wheel.writestr("sample-2.1.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n\n")
    wheel_url = f"https://files.pythonhosted.org/packages/00/00/{'0' * 60}/{filename}"
    wheel_file = descriptor("wheel", "files/source.whl", wheel_url, wheel_io.getvalue())
    release = json.dumps({"info": {"name": "sample", "version": "2.1"}, "urls": [
        {"filename": filename, "url": wheel_url, "size": wheel_file["size"],
         "digests": {"sha256": wheel_file["sha256"]}, "packagetype": "bdist_wheel"},
    ]}).encode()
    manifest = {"schemaVersion": 1, "profile": "official-v1", "collectedAt": "2026-11-08T03:10:00Z", "items": [
        {"ecosystem": "maven", "package": "x.example:a", "version": "2.1", "files": [
            descriptor("pom", "files/source.pom", "https://repo.maven.apache.org/maven2/x/example/a/2.1/a-2.1.pom", pom),
        ]},
        {"ecosystem": "python", "package": "sample", "version": "2.1", "files": [
            descriptor("pypi_release", "files/release.json", "https://pypi.org/pypi/sample/2.1/json", release), wheel_file,
        ]},
    ]}
    return manifest, {"files/source.pom": pom, "files/release.json": release, "files/source.whl": wheel_io.getvalue()}


def make_archive(manifest, files, *, special=None):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for path, data in {"manifest.json": json.dumps(manifest).encode(), **files}.items():
            item = tarfile.TarInfo(path)
            item.size = len(data)
            tar.addfile(item, BytesIO(data))
        if special is not None:
            tar.addfile(special)
    return output.getvalue()


def test_official_projection_from_native_files():
    manifest, files = example()
    items = parse_compatibility_bundle(make_archive(manifest, files))["items"]
    assert items[0]["authority"]["organization"] == "Sonatype"
    assert items[0]["evidence"]["compiler"] == {"maven.compiler.release": "11"}
    assert items[1]["authority"]["organization"] == "Python Software Foundation"
    assert items[1]["evidence"]["requiresPython"] == ">=3.10"
    assert items[1]["evidence"]["requiresDist"] == ["base>=1"]
    assert items[1]["evidence"]["tags"] == ["py3-none-any"]


def test_rejects_false_origins_inconsistent_receipts_and_unsafe_tar():
    manifest, files = example()
    for url in ("https://repo.maven.apache.org.evil.example/maven2/x/example/a/2.1/a-2.1.pom",
                "https://repo.maven.apache.org@evil.example/maven2/x/example/a/2.1/a-2.1.pom",
                "https://repo.maven.apache.org/maven2/another/artifact/2.1/artifact-2.1.pom"):
        other = deepcopy(manifest)
        other["items"][0]["files"][0]["url"] = url
        with pytest.raises(ValueError, match="Maven Central"):
            parse_compatibility_bundle(make_archive(other, files))
    with pytest.raises(ValueError, match="SHA-256"):
        parse_compatibility_bundle(make_archive(manifest, {**files, "files/source.pom": files["files/source.pom"] + b" "}))
    changed = json.loads(files["files/release.json"])
    changed["urls"][0]["digests"]["sha256"] = "f" * 64
    raw = json.dumps(changed).encode()
    other = deepcopy(manifest)
    other["items"][1]["files"][0] = descriptor("pypi_release", "files/release.json", "https://pypi.org/pypi/sample/2.1/json", raw)
    with pytest.raises(ValueError, match="PyPI 배포 정보"):
        parse_compatibility_bundle(make_archive(other, {**files, "files/release.json": raw}))
    symlink = tarfile.TarInfo("files/link")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "../../external"
    for invalid in (make_archive(manifest, files, special=symlink), make_archive(manifest, {**files, "../outside": b"x"})):
        with pytest.raises(ValueError, match="압축 경로"):
            parse_compatibility_bundle(invalid)


def test_import_is_isolated_idempotent_and_downloadable():
    manifest, files = example()
    archive = make_archive(manifest, files)
    prefix = "/api/v1/compatibility-data"
    body = {"file": ("official.tar.gz", archive, "application/gzip")}
    with TestClient(app) as client:
        assert client.get(prefix).status_code == 401
        headers = _login(client)
        existing_service = _service(client, headers)
        before = client.get("/api/v1/services").json()
        assert client.post(prefix + "/import", files=body).status_code == 403
        result = client.post(prefix + "/import", files=body, headers=headers)
        assert result.status_code == 200, result.text
        bundle = result.json()
        assert bundle["itemCount"] == 2 and len(bundle["items"]) == 2
        assert bundle["sha256"] == hashlib.sha256(archive).hexdigest()
        assert client.post(prefix + "/import", files=body, headers=headers).json()["id"] == bundle["id"]
        rejected = client.post(prefix + "/import", headers=headers, files={
            "file": ("invalid.tar.gz", archive[:10], "application/gzip"),
        })
        assert rejected.status_code == 422
        assert len(client.get(prefix).json()["bundles"]) == 1
        assert client.get(f"{prefix}/{bundle['id']}/archive").content == archive
        assert client.get("/api/v1/services").json() == before
        assert existing_service in {row["id"] for row in before}


def test_import_accepts_a_valid_archive_larger_than_the_previous_limit():
    manifest, _ = example()
    manifest["items"] = []
    files = {}
    for name in ("largea", "largeb"):
        filename = f"{name}-1.0-py3-none-any.whl"
        wheel_url = f"https://files.pythonhosted.org/packages/00/00/{'0' * 60}/{filename}"
        wheel_path = "files/" + filename
        release_path = f"files/{name}.json"
        with BytesIO() as output:
            with ZipFile(output, "w") as wheel:
                wheel.writestr(f"{name}-1.0.dist-info/METADATA", f"Name: {name}\nVersion: 1.0\n\n")
                wheel.writestr(f"{name}-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n\n")
                wheel.writestr("resource.bin", hashlib.shake_256(name.encode()).digest(9 * 1024 * 1024))
            files[wheel_path] = output.getvalue()
        wheel_file = descriptor("wheel", wheel_path, wheel_url, files[wheel_path])
        files[release_path] = json.dumps({
            "info": {"name": name, "version": "1.0"},
            "urls": [{"filename": filename, "url": wheel_url, "size": wheel_file["size"],
                      "digests": {"sha256": wheel_file["sha256"]}, "packagetype": "bdist_wheel"}],
        }).encode()
        manifest["items"].append({
            "ecosystem": "python", "package": name, "version": "1.0",
            "files": [descriptor("pypi_release", release_path, f"https://pypi.org/pypi/{name}/1.0/json",
                                 files[release_path]), wheel_file],
        })

    archive = make_archive(manifest, files)
    assert len(archive) > 16 * 1024 * 1024
    with TestClient(app) as client:
        response = client.post("/api/v1/compatibility-data/import", headers=_login(client),
                               files={"file": ("official.tar.gz", archive, "application/gzip")})
        assert response.status_code == 200, response.text
        assert response.json()["itemCount"] == 2


def test_rpm_references_require_the_oracle_package_full_version_and_architecture():
    rpm = _rpm()
    manifest = {"schemaVersion": 1, "profile": "official-v1", "collectedAt": "2026-11-08T03:10:00Z", "items": [
        {"ecosystem": "elf", "package": "zlib", "version": "1.2.11-13.el8", "architecture": "x86_64", "files": [
            descriptor("rpm", "files/source.rpm",
                       "https://yum.oracle.com/repo/OracleLinux/OL8/2/baseos/base/x86_64/getPackage/zlib-1.2.11-13.el8.x86_64.rpm", rpm),
        ]},
    ]}
    archive = make_archive(manifest, {"files/source.rpm": rpm})
    with TestClient(app) as client:
        headers = _login(client)
        response = client.post("/api/v1/compatibility-data/import", headers=headers, files={
            "file": ("official.tar.gz", archive, "application/gzip"),
        })
        assert response.status_code == 200, response.text
        with db_module.SessionLocal() as db:
            versions = {"0:1.2.11-13.el8", "1:1.2.11-13.el8", "1.2.11", "1.2.11-14.el8"}
            match = matching_references(db, "elf", "pkg:rpm/oraclelinux/zlib?arch=x86_64&distro=ol-8.2", versions)
            assert list(match) == ["0:1.2.11-13.el8"]
            assert match["0:1.2.11-13.el8"][0]["authority"]["organization"] == "Oracle"
            for wrong in ("pkg:rpm/oraclelinux/zlib?arch=aarch64&distro=ol-8.2",
                          "pkg:rpm/oraclelinux/zlib?arch=x86_64&distro=ol-8.10",
                          "pkg:rpm/redhat/zlib?arch=x86_64&distro=rhel-8.2",
                          "pkg:rpm/zlib?arch=x86_64", "pkg:rpm/oraclelinux/zlib?distro=ol-8.2"):
                assert matching_references(db, "elf", wrong, versions) == {}
