from pathlib import Path
from copy import deepcopy
import json
import subprocess
import sys

from fastapi.testclient import TestClient

from koda_tracker import db as db_module
from koda_tracker.main import app
from koda_tracker.models import Role, RolePolicy, SbomRun, ProcessingState
from koda_tracker.upgrade_batches import UpgradeBatch
from test_compatibility_bundle import example, make_archive
from test_suite_integrations import _login, _service, isolated_tracker  # noqa: F401


PREFIX = "/api/v1/upgrade-batches"
MAVEN = "pkg:maven/org.example/core"
NATIVE = "pkg:generic/libwidget"
PYTHON = "pkg:pypi/core"
SHA = "a" * 64


def upload(client, headers, service, env, coordinate, version, *, purl=None):
    name = coordinate.rsplit("/", 1)[-1]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": [
        {"type": "library", "name": name, "version": version, "purl": purl or f"{coordinate}@{version}"},
    ]}
    response = client.post("/api/v1/sbom-runs", headers=headers, data={
        "serviceId": service, "environmentId": env, "releaseVersion": version,
    }, files={"sbom": ("compatibility.cdx.json", json.dumps(bom), "application/json")})
    assert response.status_code == 202, response.text
    run_id = response.json()["runId"]
    with db_module.SessionLocal() as db:
        db.get(SbomRun, run_id).state = ProcessingState.COMPLETED
        db.commit()
    return {"runId": run_id, "sha256": response.json()["sha256"]}


def maven_evidence(version, minimum=11):
    return {"kind": "maven", "source": "offline-ci/42", "outcome": "resolved", "javaMajor": 11,
            "minimumJavaMajor": minimum, "javaRequirementEvidence": "build bytecode audit",
            "mavenVersion": "3.9.11", "reportSha256": SHA, "selected": [{"coordinate": MAVEN, "version": version}]}


def check(status, note, **platform):
    return {"status": status, "reference": note, "artifactSha256": SHA,
            "os": "Oracle Linux 8.2", "architecture": "x86_64", **platform}


def test_maven_batch_scopes_sbom_and_keeps_verification_separate():
    with TestClient(app) as client:
        headers = _login(client)
        service, other = _service(client, headers), _service(client, headers)
        environments = {item["slug"]: item["id"] for item in client.get("/api/v1/environments").json()}
        prod, dev = environments["prod"], environments["dev"]
        base = upload(client, headers, service, prod, MAVEN, "2.6")
        sbom_27 = upload(client, headers, service, prod, MAVEN, "2.7")
        sbom_28 = upload(client, headers, service, prod, MAVEN, "2.8")
        sbom_29 = upload(client, headers, service, prod, MAVEN, "2.9")
        wrong_env = upload(client, headers, service, dev, MAVEN, "2.8")
        wrong_service = upload(client, headers, other, prod, MAVEN, "2.8")
        profile = {"server": "WAS1", "os": "Oracle Linux 8.2", "architecture": "x86_64", "javaMajor": 11}
        deployment = client.put("/api/v1/java-impact/deployments", headers=headers, json={
            "runId": base["runId"], "target": profile["server"], "os": profile["os"], "architecture": "x86_64", "javaMajor": 11,
        })
        assert deployment.status_code == 200, deployment.text
        deployment_id = deployment.json()["id"]
        payload = {"schemaVersion": 1, "ecosystem": "maven", "baseline": base, "coordinate": MAVEN,
                   "deploymentId": deployment_id, "platform": {**profile, "source": "deployment-image-manifest"},
                   "candidates": [
                       {"version": "2.9", "sbom": sbom_29, "evidence": maven_evidence("2.9", 17)},
                       {"version": "2.8", "sbom": sbom_28, "evidence": maven_evidence("2.8"), "artifactSha256": SHA,
                        "build": check("passed", "CI #28", javaMajor=11), "runtime": check("failed", "smoke #28", javaMajor=11)},
                       {"version": "3.0"},
                       {"version": "2.7", "sbom": sbom_27, "evidence": maven_evidence("2.7"), "artifactSha256": SHA,
                        "build": check("passed", "CI #27", javaMajor=11), "runtime": check("passed", "smoke #27", javaMajor=11)},
                       {"version": "2.10", "evidence": {"kind": "maven", "source": "offline-ci/210", "outcome": "conflict",
                                                        "javaMajor": 11, "reasons": ["서로 배타적인 전이 버전 요구"]}},
                   ]}
        path = f"{PREFIX}/{base['runId']}"
        context = client.get(f"{path}/context")
        assert context.status_code == 200, context.text
        assert {row["runId"] for row in context.json()["candidates"]} == {sbom_27["runId"], sbom_28["runId"], sbom_29["runId"]}
        assert context.json()["javaDeployments"][0]["id"] == deployment_id
        assert client.post(PREFIX + "/import", json=payload).status_code == 403
        for foreign in (wrong_env, wrong_service):
            invalid = deepcopy(payload)
            invalid["candidates"][1]["sbom"] = foreign
            assert client.post(PREFIX + "/import", headers=headers, json=invalid).status_code == 404
        invalid = deepcopy(payload)
        invalid["candidates"][1]["sbom"]["sha256"] = "b" * 64
        assert client.post(PREFIX + "/import", headers=headers, json=invalid).status_code == 409
        invalid = deepcopy(payload)
        invalid["candidates"][1]["runtime"]["javaMajor"] = 17
        assert client.post(PREFIX + "/import", headers=headers, json=invalid).status_code == 422
        invalid = deepcopy(payload)
        invalid["candidates"][1]["sbom"] = sbom_27
        assert client.post(PREFIX + "/import", headers=headers, json=invalid).status_code == 422

        response = client.post(PREFIX + "/import", headers=headers, json=payload)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["highestConditionVersion"] == "2.8"
        assert result["highestVerifiedVersion"] == "2.7"
        assert [row["version"] for row in result["candidates"]] == ["2.7", "2.8", "2.9", "2.10", "3.0"]
        assert [row["conditionStatus"] for row in result["candidates"]] == ["conditions_met", "conditions_met", "conflict", "conflict", "unknown"]
        assert "요구 Java 17" in result["candidates"][2]["reasons"][0]
        assert result["candidates"][1]["build"]["status"] == "passed"
        assert result["candidates"][1]["runtime"]["status"] == "failed"
        assert result["candidates"][-1]["runtime"]["status"] == "not_reported"
        assert client.post(PREFIX + "/import", headers=headers, json=payload).json()["id"] == result["id"]
        assert client.get(path).json()["items"][0]["id"] == result["id"]
        assert client.get(f"{path}/{result['id']}").json() == result
        assert client.get(f"{PREFIX}/{wrong_env['runId']}/{result['id']}").status_code == 404


def test_python_and_linux_elf_share_offline_batch_contract():
    with TestClient(app) as client:
        headers = _login(client)
        service = _service(client, headers)
        prod = next(row["id"] for row in client.get("/api/v1/environments").json() if row["slug"] == "prod")
        profile = {"server": "Linux1", "os": "Oracle Linux 8.2", "architecture": "x86_64", "source": "image-64"}
        for ecosystem, coordinate in (("python", PYTHON), ("elf", NATIVE)):
            base = upload(client, headers, service, prod, coordinate, "2.8")
            candidate = upload(client, headers, service, prod, coordinate, "2.10")
            payload = {"schemaVersion": 1, "ecosystem": ecosystem, "baseline": base, "coordinate": coordinate,
                       "platform": deepcopy(profile), "candidates": [{"version": "2.10", "sbom": candidate}]}
            if ecosystem == "python":
                payload["platform"].update(pythonVersion="3.11.9", pythonImplementation="cpython", pythonSysPlatform="linux")
                evidence = {"kind": "python", "source": "pip offline CI", "outcome": "resolved",
                            "environment": {"python_full_version": "3.11.9", "implementation_name": "cpython",
                                            "sys_platform": "linux", "platform_machine": "x86_64"},
                            "pipVersion": "26.1.2", "reportSha256": SHA,
                            "packages": [{"name": "core", "version": "2.10", "requested": True, "wheelSha256": SHA}]}
            else:
                payload["platform"]["nativePlatform"] = "linux"
                elf = {"architecture": "x86_64", "elfClass": 64, "byteOrder": "little"}
                evidence = {"kind": "elf", "source": "readelf", "complete": True,
                            "consumers": [{**elf, "name": "service", "needed": [{"soname": "libwidget.so.1", "symbols": [{"name": "call", "version": "W1"}]}]}],
                            "providers": [{**elf, "soname": "libwidget.so.1", "symbols": [{"name": "call", "version": "W1"}]}]}
            payload["candidates"][0]["evidence"] = evidence
            reply = client.post(PREFIX + "/import", headers=headers, json=payload)
            assert reply.status_code == 200, reply.text
            assert reply.json()["highestConditionVersion"] == "2.10"
            assert reply.json()["highestVerifiedVersion"] is None


def test_elf_ranks_full_rpm_versions_with_purl_epoch():
    with TestClient(app) as client:
        headers = _login(client)
        service = _service(client, headers)
        prod = next(row["id"] for row in client.get("/api/v1/environments").json() if row["slug"] == "prod")
        coordinate = "pkg:rpm/ol/libwidget?arch=x86_64&distro=ol-8"
        base = upload(client, headers, service, prod, coordinate, "1.0-1.el8",
                      purl="pkg:rpm/ol/libwidget@1.0-1.el8?arch=x86_64&distro=ol-8&epoch=0")
        a = upload(client, headers, service, prod, coordinate, "2.0-1.el8",
                   purl="pkg:rpm/ol/libwidget@2.0-1.el8?arch=x86_64&distro=ol-8&epoch=0")
        b = upload(client, headers, service, prod, coordinate, "1.0^1-1.el8",
                   purl="pkg:rpm/ol/libwidget@1.0%5E1-1.el8?arch=x86_64&distro=ol-8&epoch=1")
        elf = {"architecture": "x86_64", "elfClass": 64, "byteOrder": "little"}
        evidence = {"kind": "elf", "source": "readelf", "complete": True,
                    "consumers": [{**elf, "name": "service", "needed": [{"soname": "libwidget.so.1", "symbols": []}]}],
                    "providers": [{**elf, "soname": "libwidget.so.1", "symbols": []}]}
        payload = {"schemaVersion": 1, "ecosystem": "elf", "baseline": base, "coordinate": coordinate,
                   "platform": {"server": "Linux1", "os": "Oracle Linux 8.2", "architecture": "x86_64",
                                "source": "image-64", "nativePlatform": "linux"},
                   "candidates": [{"version": "2.0-1.el8", "sbom": a, "evidence": evidence},
                                  {"version": "1:1.0^1-1.el8", "sbom": b, "evidence": evidence}]}
        response = client.post(PREFIX + "/import", headers=headers, json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["highestConditionVersion"] == "1:1.0^1-1.el8"
        assert not response.json()["orderingLimited"]


def test_existing_review_reads_imported_official_evidence_without_changing_its_result():
    manifest, files = example()
    archive = make_archive(manifest, files)
    with TestClient(app) as client:
        headers = _login(client)
        service = _service(client, headers)
        prod = next(row["id"] for row in client.get("/api/v1/environments").json() if row["slug"] == "prod")
        coordinate = "pkg:pypi/sample"
        base = upload(client, headers, service, prod, coordinate, "1.0")
        match = upload(client, headers, service, prod, coordinate, "2.1.0")
        wrong = upload(client, headers, service, prod, "pkg:pypi/unrelated", "2.1")
        inconsistent = upload(client, headers, service, prod, coordinate, "2.1", purl=coordinate + "@2.9")
        body = {"schemaVersion": 1, "ecosystem": "python", "coordinate": coordinate, "baseline": base,
                "platform": {"server": "python", "os": "Linux", "architecture": "x86_64", "source": "test",
                             "pythonVersion": "3.11.9", "pythonImplementation": "cpython", "pythonSysPlatform": "linux"},
                "candidates": [{"version": "2.1", "sbom": match}, {"version": "2.1.0", "sbom": wrong},
                               {"version": "2.1.00"}, {"version": "2.1.000", "sbom": inconsistent},
                               {"version": "2.2", "sbom": match}]}
        initial = client.post(PREFIX + "/import", json=body, headers=headers)
        assert initial.status_code == 200, initial.text
        result = initial.json()
        assert all(row["officialReferences"] == [] for row in result["candidates"])
        bundle = client.post("/api/v1/compatibility-data/import", headers=headers, files={
            "file": ("official.tar.gz", archive, "application/gzip"),
        })
        assert bundle.status_code == 200, bundle.text
        url = f"{PREFIX}/{base['runId']}/{result['id']}"
        enriched = client.get(url).json()
        assert client.post(PREFIX + "/import", json=body, headers=headers).json() == enriched
        for row in enriched["candidates"]:
            references = row.pop("officialReferences")
            if row["version"] != "2.1":
                assert references == []
                continue
            reference, = references
            assert reference["bundleId"] == bundle.json()["id"]
            assert reference["authority"]["organization"] == "Python Software Foundation"
            assert reference["version"] == "2.1"
            assert reference["evidence"]["requiresPython"] == ">=3.10"
            assert reference["files"][1]["sha256"] == manifest["items"][1]["files"][1]["sha256"]
        with db_module.SessionLocal() as db:
            stored = db.get(UpgradeBatch, result["id"]).result
            assert stored == {key: value for key, value in enriched.items() if key != "id"}
            policy = db.get(RolePolicy, Role.ADMIN)
            policy.permissions = [name for name in policy.permissions if not name.startswith("metadata.")]
            db.commit()
        assert client.get("/api/v1/compatibility-data").status_code == 403
        assert client.get(url).json() == enriched


def test_project_maven_native_report(tmp_path):
    path = tmp_path / "native.json"
    path.write_text(json.dumps({"groupId": "org.example", "artifactId": "app", "children": [
        {"groupId": "org.example", "artifactId": "core", "version": "2.8", "scope": "compile", "children": [
            {"groupId": "org.example", "artifactId": "utility", "version": "1.0", "scope": "runtime"},
        ]},
    ]}))
    script = Path(__file__).resolve().parents[2] / "scripts" / "project-maven-upgrade-report.py"
    run = subprocess.run([sys.executable, str(script), str(path), "--source", "CI-38", "--maven-version", "3.9.11",
                          "--java-major", "11", "--minimum-java-major", "11", "--java-requirement-evidence", "audit"],
                         check=True, capture_output=True, text=True)
    evidence = json.loads(run.stdout)
    assert evidence["outcome"] == "resolved" and len(evidence["reportSha256"]) == 64
    assert evidence["selected"] == [{"coordinate": MAVEN, "version": "2.8"},
                                    {"coordinate": "pkg:maven/org.example/utility", "version": "1.0"}]
