from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pydantic import SecretStr

from koda_tracker.config import get_settings
from koda_tracker import db as db_module, identity_suggestions as identity_module, main as main_module
from koda_tracker.external_api import ExternalReadToken
from koda_tracker.main import app
from koda_tracker.models import AnalysisRevision, JobState, ProcessingState, SbomRun, now
from koda_tracker.shared_ai import SharedAISettings
from koda_tracker.upgrade_batches import UpgradeBatch

EXTERNAL = "/api/v1/integrations/external"
JAVA = "/api/v1/java-impact"
AI = "/api/v1/ai"
COORDINATE = "pkg:maven/org.example/app-core"


@pytest.fixture(autouse=True)
def isolated_tracker(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'suite-integrations.db'}", connect_args={"check_same_thread": False})
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "SessionLocal", session)
    monkeypatch.setattr(db_module, "SessionLocal", session)
    monkeypatch.setattr(get_settings(), "artifact_dir", tmp_path / "artifacts")
    try:
        yield
    finally:
        engine.dispose()


def _login(client):
    response = client.post("/api/v1/auth/login", json={
        "username": "test-admin", "password": "correct-horse-battery-staple",
    })
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrfToken"]}


def _service(client, headers):
    response = client.post("/api/v1/services", json={"slug": f"test-{uuid4().hex[:12]}", "name": "테스트 서비스"}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _run(client, headers, service, environment, version, cve, digest="a" * 64, additional_version=None, extra=()):
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": "example", "bom-ref": "root"}},
        "components": [
            {"type": "library", "name": "gateway", "version": "1.0", "bom-ref": "gateway", "purl": "pkg:maven/org.example/gateway@1.0"},
            {"type": "library", "name": "app-core", "version": version, "bom-ref": "core",
             "purl": f"{COORDINATE}@{version}?type=jar"},
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["gateway"]}, {"ref": "gateway", "dependsOn": ["core"]}],
    }
    if additional_version:
        bom["components"].append({"type": "library", "name": "app-core", "version": additional_version,
                                  "bom-ref": "core-additional", "purl": f"{COORDINATE}@{additional_version}?type=jar"})
        bom["dependencies"][1]["dependsOn"].append("core-additional")
    bom["components"].extend(extra)
    response = client.post("/api/v1/sbom-runs", data={
        "serviceId": service, "environmentId": environment, "releaseVersion": version,
    }, files={"sbom": ("integration.cdx.json", json.dumps(bom).encode(), "application/json")}, headers=headers)
    assert response.status_code == 202, response.text
    run_id = response.json()["runId"]
    with db_module.SessionLocal() as db:
        run = db.get(SbomRun, run_id)
        run.state = ProcessingState.COMPLETED
        run.analysis_state = JobState.COMPLETED
        db.add(AnalysisRevision(run_id=run_id, sequence=1, state=JobState.COMPLETED, tool_version="grype/test",
                                data_sources={"bundleManifestSha256": digest, "sbomNormalization": {"version": 2}},
                                findings=[{"id": cve, "canonicalId": cve, "severity": "high", "component": COORDINATE,
                                           "version": version, "description": "must-not-leave", "path": "/private/source"}]))
        db.commit()
    return run_id


def test_external_token_scope_and_read_only_java_impact():
    with TestClient(app) as client:
        csrf = _login(client)
        service, other_service = _service(client, csrf), _service(client, csrf)
        environments = {item["slug"]: item["id"] for item in client.get("/api/v1/environments").json()}
        prod, dev = environments["prod"], environments["dev"]
        base = _run(client, csrf, service, prod, "1.0", "CVE-2025-10101")
        candidate = _run(client, csrf, service, prod, "2.0", "CVE-2025-10102", additional_version="2.1")
        other_env = _run(client, csrf, service, dev, "3.0", "CVE-2025-10103")
        other = _run(client, csrf, other_service, prod, "4.0", "CVE-2025-10104")
        uncomparable = _run(client, csrf, service, prod, "5.0", "CVE-2025-10105", digest="b" * 64)

        token_body = {"name": "ops dashboard", "serviceId": service, "environmentId": prod, "days": 1}
        assert client.post(EXTERNAL + "/tokens", json=token_body).status_code == 403
        issued = client.post(EXTERNAL + "/tokens", json=token_body, headers=csrf)
        assert issued.status_code == 201, issued.text
        assert issued.headers["Cache-Control"] == "no-store"
        token = issued.json()
        headers = {"Authorization": f"Bearer {token['token']}"}
        assert token["token"] not in client.get(EXTERNAL + "/tokens").text
        schema = client.get("/openapi.json").json()
        assert {"TrackerReadToken": []} in schema["paths"][EXTERNAL + "/runs"]["get"]["security"]
        assert client.get(EXTERNAL + "/runs").status_code == 401
        assert client.get(EXTERNAL + "/scope", headers=headers).json()["environments"] == [{"id": prod, "name": "운영"}]
        assert client.get(EXTERNAL + "/runs", params={"size": 1}, headers=headers).json()["total"] == 3
        assert client.get(EXTERNAL + f"/runs/{base}", headers=headers).json()["id"] == base
        for hidden in (other_env, other):
            assert client.get(EXTERNAL + f"/runs/{hidden}/components", headers=headers).status_code == 404
        rows = client.get(EXTERNAL + f"/runs/{base}/components", headers=headers).json()["items"]
        assert any(row["purl"].startswith(COORDINATE) for row in rows), rows
        findings = client.get(EXTERNAL + f"/runs/{base}/findings", headers=headers)
        assert findings.status_code == 200
        assert "CVE-2025-10101" in findings.text and "must-not-leave" not in findings.text
        compared = client.get(EXTERNAL + "/comparison", params={"baseRunId": base, "targetRunId": candidate}, headers=headers)
        assert compared.status_code == 200, compared.text
        assert "componentsChanged" in compared.json()["summary"]
        assert client.get(EXTERNAL + "/comparison", params={"baseRunId": base, "targetRunId": other}, headers=headers).status_code == 404

        def register(run, target):
            response = client.put(JAVA + "/deployments", headers=csrf, json={
                "runId": run, "target": target, "javaMajor": 11, "os": "Oracle Linux 8.2", "architecture": "x86_64",
            })
            assert response.status_code == 200, response.text
            return response.json()["id"]

        deployment = register(base, "production-was")
        assert register(base, "production-was") == deployment
        hidden_deployment = register(other_env, "internal-dev")
        cross_service_deployment = register(other, "other-was")
        params = {"deploymentId": deployment, "coordinate": COORDINATE, "candidateRunId": candidate,
                  "minimumJavaMajor": 17, "requirementEvidence": "fixture release note"}
        assert client.post(JAVA + "/assessments", json=params).status_code == 403
        assessment = client.post(JAVA + "/assessments", json=params, headers=csrf)
        assert assessment.status_code == 200, assessment.text
        result = assessment.json()
        assert result["status"] == "declared_conflict"
        assert result["currentVersions"] == ["1.0"] and result["candidateVersions"] == ["2.0", "2.1"]
        assert any(change["baseVersions"] == ["1.0"] and change["targetVersions"] == ["2.0", "2.1"]
                   for change in result["componentChanges"])
        assert result["dependencyPaths"] == [["root", "gateway", "core"]]
        assert {row["id"] for row in result["affectedDeployments"]} == {deployment, hidden_deployment, cross_service_deployment}
        assert result["vulnerabilityComparison"]["removed"] == ["CVE-2025-10101"]
        assert result["vulnerabilityComparison"]["added"] == ["CVE-2025-10102"]
        assert result["runtimeTest"] == "not_run"
        mismatch = client.post(JAVA + "/assessments", json={**params, "candidateRunId": uncomparable}, headers=csrf)
        assert mismatch.json()["vulnerabilityComparison"]["status"] == "not_comparable"
        manual = client.post(JAVA + "/assessments", json={"deploymentId": deployment, "coordinate": COORDINATE, "candidateVersion": "2.1"}, headers=csrf)
        assert manual.json()["status"] == "needs_verification"
        assert manual.json()["componentChanges"] is None
        assert client.post(JAVA + "/assessments", json={**params, "candidateRunId": other}, headers=csrf).status_code == 422
        assert {row["id"] for row in client.get(EXTERNAL + "/java-deployments", headers=headers).json()["items"]} == {deployment}
        external_result = client.post(EXTERNAL + "/upgrade-assessments", json=params, headers=headers)
        assert external_result.status_code == 200, external_result.text
        assert [row["id"] for row in external_result.json()["affectedDeployments"]] == [deployment]
        assert client.post(EXTERNAL + "/upgrade-assessments", json={**params, "candidateRunId": other_env}, headers=headers).status_code == 404

        legacy = client.post("/api/v1/api-tokens", json={"name": "legacy uploader", "serviceId": service}, headers=csrf)
        assert legacy.status_code == 201, legacy.text
        with TestClient(app) as anonymous:
            assert anonymous.get(EXTERNAL + "/runs", headers={"Authorization": f"Bearer {legacy.json()['token']}"}).status_code == 401
            assert anonymous.post("/api/v1/sbom-runs", headers=headers, files={"sbom": ("test.json", b"{}")}).status_code == 401
        with db_module.SessionLocal() as db:
            record = db.get(ExternalReadToken, token["id"])
            assert record.token_hash != token["token"]
            record.expires_at = now() - timedelta(seconds=1)
            db.commit()
        assert client.get(EXTERNAL + "/runs", headers=headers).status_code == 401
        assert client.post(EXTERNAL + f"/tokens/{token['id']}/revoke", headers=csrf).json()["revokedAt"]


def test_shared_private_ai_provider_for_koda_and_tracker(monkeypatch):
    requests = []

    class Model(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append((self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": "검토 참고"}}]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}/v1"
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_base_url", "")
    monkeypatch.setattr(settings, "ai_encryption_key", SecretStr(Fernet.generate_key().decode()))
    try:
        with TestClient(app) as client:
            csrf = _login(client)
            service = _service(client, csrf)
            env = next(item["id"] for item in client.get("/api/v1/environments").json() if item["slug"] == "prod")
            run_id = _run(client, csrf, service, env, "1.0", "CVE-2025-30301")
            secret = "private-model-fixture-secret"
            assert client.get(AI + "/settings").json()["baseUrl"] is None
            monkeypatch.setattr(settings, "ai_base_url", endpoint)
            assert client.get(AI + "/settings").json()["baseUrl"] == endpoint
            monkeypatch.setattr(settings, "ai_base_url", "")
            body = {"baseUrl": endpoint, "model": "internal-model", "apiKey": secret}
            assert client.put(AI + "/settings", json=body).status_code == 403
            response = client.put(AI + "/settings", json=body, headers=csrf)
            assert response.status_code == 200, response.text
            assert response.json()["hasKey"] and secret not in response.text
            with db_module.SessionLocal() as db:
                assert db.get(SharedAISettings, 1).encrypted_key != secret
            assert client.post(AI + "/test", headers=csrf).json() == {"ok": True}
            tracker = client.post(AI + f"/runs/{run_id}/summary", headers=csrf)
            assert tracker.json() == {"summary": "검토 참고", "model": "internal-model", "advisory": True}
            endpoint_path = "/api/v1/integrations/koda/ai-summary"
            facts = {"severityCounts": {"high": 2}, "ruleIds": ["JAVA.001"]}
            assert client.post(endpoint_path, json=facts).status_code == 401
            koda_headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
            assert client.post(endpoint_path, json={**facts, "ruleIds": ["/private/source"]}, headers=koda_headers).status_code == 422
            koda = client.post(endpoint_path, json=facts, headers=koda_headers)
            assert koda.json() == tracker.json()
            assert all(path == "/v1/chat/completions" and auth == f"Bearer {secret}" for path, auth, _ in requests)
            assert [row[2]["model"] for row in requests] == ["internal-model"] * 3
            tracker_facts = json.loads(requests[1][2]["messages"][1]["content"])
            assert tracker_facts == {"source": "tracker", "severityCounts": {"high": 1}, "cves": ["CVE-2025-30301"]}
            assert json.loads(requests[2][2]["messages"][1]["content"]) == {"source": "koda", **facts}

            for disallowed in ("https://8.8.8.8/v1", "http://169.254.169.254/v1",
                               "https://name:password@127.0.0.1/v1", "http://127.0.0.1/wrong"):
                assert client.put(AI + "/settings", json={"model": "internal-model", "baseUrl": disallowed},
                                  headers=csrf).status_code == 422
            assert client.put(AI + "/settings", json={"model": "internal-model", "baseUrl": "http://10.0.0.3/v1",
                              "apiKey": "demo-key"}, headers=csrf).status_code == 422
            assert client.put(AI + "/settings", json={"model": "internal-model"}, headers=csrf).json()["hasKey"]
            assert client.get(AI + "/settings").json()["hasKey"]
            assert len(requests) == 3
            changed = client.put(AI + "/settings", json={"model": "internal-model",
                                  "baseUrl": endpoint.replace("127.0.0.1", "127.0.0.2")}, headers=csrf)
            assert changed.status_code == 200, changed.text
            assert changed.json()["baseUrl"] != endpoint and not changed.json()["hasKey"]
            assert not client.get(AI + "/settings").json()["hasKey"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_koda_finding_review_uses_private_provider_and_validates_advice(monkeypatch):
    calls = []
    review = {
        "verdict": "needs_review",
        "reasoning": "호출 조건을 확인할 근거가 부족합니다.",
        "impact": "점검에 포함된 파일과 구성요소만 확인했습니다.",
        "remediation": "확인된 입력 검증을 유지하고 검사 범위를 확인하세요.",
        "retest": "정상 입력의 회귀 테스트와 KODA 재점검을 수행하세요.",
    }
    reply = json.dumps(review)

    class Model(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": reply}}]}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(app) as client:
            path = "/api/v1/integrations/koda/ai-finding-review"
            headers = {"Authorization": "Bearer test-koda-provisioning-secret"}
            source = {"kind": "source", "facts": {"ruleId": "code.example", "severity": "high", "title": "검증 누락",
                      "sourceContext": 'token = "fixture-must-stay-private"\nvalidate(value)',
                      "trace": "app.py:18", "package": "not-relevant"}}
            assert client.post(path, json=source).status_code == 401
            assert client.post(path, json=source, headers=headers).status_code == 503
            oversized = "fixture-must-stay-private" * 400
            invalid = client.post(path, headers=headers, json={**source, "facts": {**source["facts"], "sourceContext": oversized}})
            assert invalid.status_code == 422 and "fixture-must-stay-private" not in invalid.text
            assert client.post(path, headers=headers, json={**source, "rawFiles": []}).status_code == 422
            assert not calls

            csrf = _login(client)
            configured = client.put(AI + "/settings", headers=csrf, json={
                "baseUrl": f"http://127.0.0.1:{server.server_port}/v1", "model": "internal-model",
            })
            assert configured.status_code == 200, configured.text
            response = client.post(path, json=source, headers=headers)
            assert response.status_code == 200, response.text
            assert response.headers["Cache-Control"] == "no-store"
            assert response.json() == {"model": "internal-model", "review": review, "advisory": True}
            assert set(calls[0]) == {"model", "max_tokens", "stream", "messages"}
            payload = json.loads(calls[0]["messages"][1]["content"])
            assert payload["kind"] == "source"
            assert payload["facts"]["sourceContext"] == "[REDACTED]\nvalidate(value)"
            assert "package" not in payload["facts"]

            library = {"kind": "library", "facts": {"ruleId": "dependency.example", "severity": "high",
                       "package": "pkg:pypi/demo@1.0", "vulnerabilityId": "CVE-2025-30301", "fixedVersions": "1.1",
                       "sourceContext": "must-not-leave"}}
            assert client.post(path, json=library, headers=headers).status_code == 200
            payload = json.loads(calls[1]["messages"][1]["content"])
            assert payload == {"kind": "library", "facts": {k: v for k, v in library["facts"].items() if k != "sourceContext"}}

            secret = {**source, "facts": {**source["facts"], "ruleId": "secret.private-key", "evidence": "opaque"}}
            assert client.post(path, json=secret, headers=headers).status_code == 200
            assert json.loads(calls[2]["messages"][1]["content"])["facts"] == {"ruleId": "secret.private-key", "severity": "high"}

            for invalid_review in ({**review, "verdict": "confirmed"}, {**review, "impact": "  "},
                                   {**review, "steps": []}, {**review, "retest": "```unstructured```"}):
                reply = json.dumps(invalid_review)
                response = client.post(path, json=source, headers=headers)
                assert response.status_code == 502
                assert "unstructured" not in response.text
            reply = json.dumps({**review, "impact": "password='model-fixture-secret'"})
            response = client.post(path, json=source, headers=headers)
            assert response.json()["review"]["impact"] == "[REDACTED]"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ai_assists_explain_tracker_results_without_deciding_them(monkeypatch):
    calls = []
    reply = {"content": ""}

    class Model(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"choices": [{"message": {"content": reply["content"]}}]}).encode())

        def log_message(self, *args):
            pass

    def facts(index=-1):
        return json.loads(calls[index]["messages"][1]["content"])

    class Index:
        def items(self, query):
            for identifier, record in RECORDS:
                if query in record["descriptions"][0]["value"].casefold():
                    yield identifier, record

    def leaf(cpe):
        return {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]}]}

    RECORDS = [
        ("CVE-2024-0001", {"descriptions": [{"lang": "en", "value": "Issue in OpenSSL ssl handling"}],
                           **leaf("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")}),
        ("CVE-2024-0002", {"descriptions": [{"lang": "en", "value": "Issue in LibreSSL ssl handling"}],
                           **leaf("cpe:2.3:a:openbsd:libressl:*:*:*:*:*:*:*:*")}),
        ("CVE-2024-0003", {"descriptions": [{"lang": "en", "value": "Unrelated ssl text"}],
                           **leaf("cpe:2.3:a:other:dashboard:*:*:*:*:*:*:*:*")}),
    ]

    @contextmanager
    def release():
        yield None, Index(), {"dataAsOf": "2026-11-01"}

    monkeypatch.setattr(identity_module, "catalog_release", release)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(app) as client:
            csrf = _login(client)
            service = _service(client, csrf)
            env = next(item["id"] for item in client.get("/api/v1/environments").json() if item["slug"] == "prod")
            native = {"type": "library", "name": "libssl.so.1.1", "version": "1.1.1k", "bom-ref": "native-ssl"}
            base = _run(client, csrf, service, env, "1.0", "CVE-2025-20001")
            target = _run(client, csrf, service, env, "2.0", "CVE-2025-20002", extra=[native])
            briefing_body = {"baseRunId": base, "targetRunId": target}
            assert client.post("/api/v1/comparisons/ai-briefing", json=briefing_body).status_code == 403
            assert client.post("/api/v1/comparisons/ai-briefing", json=briefing_body, headers=csrf).status_code == 503
            configured = client.put(AI + "/settings", headers=csrf, json={
                "baseUrl": f"http://127.0.0.1:{server.server_port}/v1", "model": "internal-model"})
            assert configured.status_code == 200, configured.text

            # 6. Comparison briefing: computed diff in, structured advice out; hashes and run IDs stay home.
            briefing = {"newRisks": "CVE-2025-20002가 새로 발견되었습니다.", "resolvedRisks": "CVE-2025-20001이 해소되었습니다.",
                        "approvalChecks": ["신규 고위험 취약점의 수정 버전을 확인하세요."]}
            reply["content"] = json.dumps(briefing)
            response = client.post("/api/v1/comparisons/ai-briefing", json=briefing_body, headers=csrf)
            assert response.status_code == 200, response.text
            assert response.json() == {"model": "internal-model", "briefing": briefing, "truncated": [], "advisory": True}
            sent = facts()
            assert [row["id"] for row in sent["vulnerabilities"]["added"]] == ["CVE-2025-20002"]
            assert [row["id"] for row in sent["vulnerabilities"]["removed"]] == ["CVE-2025-20001"]
            assert {row["name"] for row in sent["components"]["added"]} == {"libssl.so.1.1"}
            raw = calls[-1]["messages"][1]["content"]
            assert base not in raw and target not in raw and "a" * 64 not in raw and "must-not-leave" not in raw
            for invalid in ({**briefing, "verdict": "safe"}, {**briefing, "newRisks": " "},
                            {**briefing, "approvalChecks": ["x"] * 9}):
                reply["content"] = json.dumps(invalid)
                assert client.post("/api/v1/comparisons/ai-briefing", json=briefing_body, headers=csrf).status_code == 502
            reply["content"] = "자유 형식 답변"
            assert client.post("/api/v1/comparisons/ai-briefing", json=briefing_body, headers=csrf).status_code == 502

            # 5. Upgrade explanation: engine picks stay as stored; host labels never leave; unknown versions dropped.
            with db_module.SessionLocal() as db:
                run = db.get(SbomRun, base)
                batch = UpgradeBatch(baseline_run_id=base, manifest_sha256="c" * 64, result={
                    "schemaVersion": 1, "manifestSha256": "c" * 64, "createdAt": now().isoformat(), "importedBy": "test-admin",
                    "baseline": {"runId": base, "sha256": run.sha256}, "serviceId": run.release.service_id,
                    "environmentId": run.release.environment_id, "ecosystem": "maven", "coordinate": COORDINATE,
                    "deploymentId": None, "platform": {"server": "build-host-private", "source": "ops-ledger", "os": "linux",
                                                       "architecture": "x86_64", "javaMajor": 17},
                    "currentVersions": ["1.0"], "highestConditionVersion": "1.2", "highestVerifiedVersion": None,
                    "orderingLimited": False, "candidates": [
                        {"version": "1.2", "sbom": None, "conditionStatus": "conditions_met", "reasons": ["Java 17 충족"],
                         "evidenceSource": None, "reportSha256": None, "artifactSha256": None,
                         "build": {"status": "not_reported"}, "runtime": {"status": "not_reported"}},
                        {"version": "2.0", "sbom": None, "conditionStatus": "conflict", "reasons": ["Java 21 필요"],
                         "evidenceSource": None, "reportSha256": None, "artifactSha256": None,
                         "build": {"status": "not_reported"}, "runtime": {"status": "not_reported"}}]})
                db.add(batch)
                db.commit()
                batch_id = batch.id
            explanation = {"summary": "엔진이 1.2를 조건 충족 최고 버전으로 판정했습니다.",
                           "candidates": [{"version": "1.2", "note": "Java 17 조건 충족"},
                                          {"version": "9.9", "note": "모델이 만든 버전"}],
                           "checklist": ["빌드·실행 기록을 반입하세요."]}
            reply["content"] = json.dumps(explanation)
            path = f"/api/v1/upgrade-batches/{base}/{batch_id}/ai-explanation"
            assert client.post(path).status_code == 403
            response = client.post(path, headers=csrf)
            assert response.status_code == 200, response.text
            assert [row["version"] for row in response.json()["explanation"]["candidates"]] == ["1.2"]
            sent = facts()
            assert sent["highestConditionVersion"] == "1.2" and sent["platform"] == {
                "os": "linux", "architecture": "x86_64", "javaMajor": 17}
            assert "build-host-private" not in calls[-1]["messages"][1]["content"]
            assert client.post(f"/api/v1/upgrade-batches/{target}/{batch_id}/ai-explanation", headers=csrf).status_code == 404

            # 3. Identity suggestions: candidates only from the NVD index; the model ranks, never invents.
            components = client.get(f"/api/v1/sbom-runs/{target}/components", params={"size": 100}).json()["items"]
            native_key = next(row["identityKey"] for row in components if row["name"] == "libssl.so.1.1")
            purl_key = next(row["identityKey"] for row in components if row["purl"])
            identity_path = AI + f"/runs/{target}/identity-suggestions"
            assert client.post(identity_path, json={"identityKey": native_key}).status_code == 403
            assert client.post(identity_path, json={"identityKey": purl_key}, headers=csrf).status_code == 409
            assert client.post(identity_path, json={"identityKey": "missing"}, headers=csrf).status_code == 404
            reply["content"] = json.dumps({"ranking": [
                {"candidate": "c1", "confidence": "high", "reason": "libssl은 OpenSSL의 라이브러리입니다."},
                {"candidate": "c9", "confidence": "high", "reason": "후보 밖"}]})
            response = client.post(identity_path, json={"identityKey": native_key}, headers=csrf)
            assert response.status_code == 200, response.text
            result = response.json()
            sent = facts()
            assert {row["product"] for row in sent["candidates"]} == {"openssl", "libressl"}
            assert sent["component"]["name"] == "libssl.so.1.1"
            assert [row["id"] for row in result["candidates"]] == ["c1", "c0"]
            top = result["candidates"][0]
            assert top["confidence"] == "high" and top["product"] in {"openssl", "libressl"}
            assert top["cpe"] == f"cpe:2.3:a:{top['vendor']}:{top['product']}:1.1.1k:*:*:*:*:*:*:*"
            assert result["candidates"][1]["confidence"] is None and result["dataAsOf"] == "2026-11-01"
            RECORDS.clear()
            before = len(calls)
            empty = client.post(identity_path, json={"identityKey": native_key}, headers=csrf).json()
            assert empty["candidates"] == [] and len(calls) == before
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_identity_candidates_search_readable_names_and_compare_squashed_forms():
    assert identity_module._search_terms("log4j-core-2.14.1.jar")[:2] == ["log4j-core", "log4j"]
    assert identity_module._name_forms("jackson-databind-2.9.10.1") == {"jacksondatabind"}
    assert identity_module._name_forms("libssl.so.1.1") == {"libssl", "ssl"}
    queries = []

    class Index:
        def items(self, query):
            queries.append(query)
            text = {"log4j-core": "apache log4j-core jndi issue", "log4j": "apache log4j issue"}
            if query in text:
                yield "CVE-2021-44228", {"descriptions": [{"lang": "en", "value": text[query]}], "configurations": [
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}]}]}]}

    rows = identity_module.nvd_candidates(Index(), "log4j-core-2.14.1.jar", "org.apache.logging.log4j")
    assert queries[0] == "log4j-core"
    assert [(row["vendor"], row["product"], row["match"]) for row in rows] == [("apache", "log4j", "partial")]
