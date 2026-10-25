#!/usr/bin/env python3
"""Exercise the real native stack through its gateway and retain safe evidence.

Run against an isolated verification Compose project. This creates test catalog,
user, token and SBOM records, and temporarily changes the global policy document.
The original policy is restored as a new version, including on failure. No user
data or volumes are deleted. Grype is executed by the actual queued worker.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import time
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener
import uuid


class VerificationError(RuntimeError):
    pass


def dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, raw = line.split("=", 1)
        parts = shlex.split(raw, comments=True)
        result[name.strip()] = " ".join(parts)
    return result


class Client:
    def __init__(self, base: str, *, bearer: str | None = None):
        self.base = base.rstrip("/")
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""
        self.bearer = bearer

    def request(self, method: str, path: str, *, data=None, raw: bytes | None = None,
                content_type: str | None = None, expected: int = 200, as_bytes: bool = False,
                extra_headers: dict | None = None):
        headers = dict(extra_headers or {})
        if data is not None:
            raw = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        elif content_type:
            headers["Content-Type"] = content_type
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if self.bearer:
            headers["Authorization"] = f"Bearer {self.bearer}"
        request = Request(self.base + path, data=raw, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=45) as response:
                status, body = response.status, response.read()
        except HTTPError as error:
            status, body = error.code, error.read()
        if status != expected:
            raise VerificationError(f"{method} {path}: expected HTTP {expected}, got {status}: {body.decode(errors='replace')[:1500]}")
        if as_bytes:
            return body
        return json.loads(body) if body else None

    def login(self, username: str, password: str):
        payload = self.request("POST", "/api/v1/auth/login", data={"username": username, "password": password})
        self.csrf = payload["csrfToken"]
        return payload["user"]

    def upload(self, bom: bytes, fields: dict[str, str], *, idempotency_key: str):
        boundary = f"koda-native-{uuid.uuid4().hex}"
        parts: list[bytes] = []
        for name, value in fields.items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        parts.extend([
            f'--{boundary}\r\nContent-Disposition: form-data; name="sbom"; filename="native-runtime.cdx.json"\r\nContent-Type: application/json\r\n\r\n'.encode(),
            bom, f"\r\n--{boundary}--\r\n".encode(),
        ])
        return self.request("POST", "/api/v1/sbom-runs", raw=b"".join(parts),
                            content_type=f"multipart/form-data; boundary={boundary}", expected=202,
                            extra_headers={"Idempotency-Key": idempotency_key})


def make_bom(log4j: str, lodash: str) -> bytes:
    components = [
        {"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": log4j,
         "purl": f"pkg:maven/org.apache.logging.log4j/log4j-core@{log4j}",
         "bom-ref": f"pkg:maven/org.apache.logging.log4j/log4j-core@{log4j}", "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"type": "library", "name": "lodash", "version": lodash, "purl": f"pkg:npm/lodash@{lodash}",
         "bom-ref": f"pkg:npm/lodash@{lodash}", "licenses": [{"license": {"id": "MIT"}}]},
    ]
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                       "version": 1, "metadata": {"component": {"type": "application", "name": "native-runtime-verification", "version": "1.0"}},
                       "components": components}, indent=2).encode()


def run(args) -> tuple[dict, list[str]]:
    env = dotenv(args.env_file)
    password = env.get("TRACKER_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not password:
        raise VerificationError("The verification env must contain a bootstrap admin password")
    admin = Client(args.base_url)
    report = {"startedAt": datetime.now(UTC).isoformat(), "baseUrl": args.base_url,
              "composeProject": env.get("COMPOSE_PROJECT_NAME"), "checks": [], "evidence": {}}
    hidden = [password]
    current_authored_version = None
    original_policy = None
    token_id = None

    def check(name: str, condition: bool, evidence=None):
        if not condition:
            raise VerificationError(f"Check failed: {name}")
        report["checks"].append({"name": name, "passed": True, "evidence": evidence})
        print(f"PASS {name}", flush=True)

    def job_finished(job_id: str):
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            job = admin.request("GET", f"/api/v1/jobs/{job_id}")
            if job["state"] in {"completed", "failed"}:
                report["evidence"].setdefault("jobs", []).append(job)
                check("worker job completed", job["state"] == "completed", job)
                return job
            time.sleep(2)
        raise VerificationError(f"Worker job timed out after {args.timeout}s: {job_id}")

    def detail(run_id: str):
        return admin.request("GET", f"/api/v1/sbom-runs/{run_id}")

    def records(run_id: str, analysis_id: str):
        values, page = [], 1
        while True:
            payload = admin.request("GET", f"/api/v1/sbom-runs/{run_id}/policy-violations?" + urlencode({"analysisId": analysis_id, "size": 100, "page": page}))
            values.extend(payload["items"])
            if len(values) >= payload["total"]:
                return values
            page += 1
            if page > 1000:
                raise VerificationError("Policy result pagination exceeded expected evaluation bound")

    try:
        check("gateway health", admin.request("GET", "/healthz", as_bytes=True).strip() == b"ok")
        user = admin.login(env.get("TRACKER_BOOTSTRAP_ADMIN_USERNAME", "admin"), password)
        hidden.append(admin.csrf)
        check("admin cookie authentication", "policies.manage" in user["permissions"])
        original_policy = admin.request("GET", "/api/v1/sbom-policies")
        unique = uuid.uuid4().hex[:10]
        runtime_rule = {"id": f"runtime-severity-{unique}", "name": "실제 Grype 검증용 심각도 정책", "kind": "severity",
                        "enabled": True, "action": "fail", "values": ["critical", "high"]}
        policy = admin.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": original_policy["version"],
                               "rules": [*original_policy["rules"], runtime_rule], "exceptions": original_policy["exceptions"]})
        current_authored_version = policy["version"]
        check("native policy version persisted", admin.request("GET", "/api/v1/sbom-policies")["version"] == policy["version"])
        service = admin.request("POST", "/api/v1/services", data={"slug": f"native-runtime-{unique}", "name": f"실제 Grype 검증 {unique}"}, expected=201)
        environments = admin.request("GET", "/api/v1/environments")
        check("environment catalog available", bool(environments))
        environment = next((item for item in environments if item["slug"] == "dev"), environments[0])
        fields = {"serviceId": service["id"], "environmentId": environment["id"], "releaseVersion": f"runtime-{unique}"}
        vulnerable_bom, fixed_bom = make_bom("2.14.1", "4.17.20"), make_bom("2.25.3", "4.17.21")
        (args.output_dir / "vulnerable.cdx.json").write_bytes(vulnerable_bom)
        (args.output_dir / "comparison.cdx.json").write_bytes(fixed_bom)
        first_upload = admin.upload(vulnerable_bom, fields, idempotency_key=f"runtime-{unique}-first")
        replay = admin.upload(vulnerable_bom, fields, idempotency_key=f"runtime-{unique}-first")
        check("upload idempotency", replay["runId"] == first_upload["runId"] and replay.get("idempotentReplay") is True)
        first_id = first_upload["runId"]
        report["evidence"]["service"] = service
        report["evidence"]["uploads"] = [first_upload]
        job_finished(first_upload["jobId"])
        first = detail(first_id)
        first_analysis = first["analyses"][0]
        first_records = records(first_id, first_analysis["id"])
        report["evidence"].update({"initialRun": first, "initialPolicies": first_records})
        tool_version = str(first_analysis.get("toolVersion") or "")
        check("real Grype tool version", bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+].*)?", tool_version)), tool_version)
        check("native Grype analysis completed", first["state"] == "completed" and first["analysisState"] == "completed" and first["policyState"] == "completed")
        check("real vulnerable SBOM has CVE findings", first["vulnerabilityCount"] > 0, {"count": first["vulnerabilityCount"], "dataAsOf": first["dataAsOf"]})
        check("real policy violation produced", first["policyStatus"] == "fail" and any(row.get("policyId") == runtime_rule["id"] and row.get("vulnerabilityId", "").startswith("CVE-") and not row.get("suppressed") for row in first_records), {"status": first["policyStatus"], "count": first["policyViolationCount"]})
        check("native metrics agree with API", first["componentCount"] == 2 and first["analysisMetrics"]["componentCount"] == 2 and first["analysisMetrics"]["vulnerabilityCount"] == first["vulnerabilityCount"])
        check("policy snapshot matches applied version", first_analysis["policyVersion"] == policy["version"] and first_analysis["policySnapshot"]["rules"] == policy["rules"])
        components = admin.request("GET", f"/api/v1/sbom-runs/{first_id}/components?size=100")
        check("component explorer/search", components["total"] == 2 and admin.request("GET", f"/api/v1/sbom-runs/{first_id}/components?q=log4j")["total"] == 1)
        findings = admin.request("GET", f"/api/v1/sbom-runs/{first_id}/findings?size=100")
        report["evidence"]["initialFindings"] = findings
        check("findings explorer", findings["total"] == first["vulnerabilityCount"])
        one = admin.request("GET", f"/api/v1/sbom-runs/{first_id}/policy-violations?size=1")
        check("policy result server pagination", len(one["items"]) == 1 and one["total"] == len(first_records))
        artifact = admin.request("GET", f"/api/v1/sbom-runs/{first_id}/artifact", as_bytes=True)
        check("original artifact download SHA256", hashlib.sha256(artifact).hexdigest() == hashlib.sha256(vulnerable_bom).hexdigest() == first["sha256"])
        selected = next(row for row in first_records if row.get("policyId") == runtime_rule["id"] and row.get("vulnerabilityId", "").startswith("CVE-") and not row.get("suppressed"))
        exception = {"id": f"runtime-exception-{unique}", "ruleId": runtime_rule["id"], "component": selected["component"],
                     "vulnerabilityId": selected["vulnerabilityId"], "reason": "실제 Grype 정책 예외 저장·재평가 검증",
                     "expiresAt": (datetime.now(UTC) + timedelta(days=1)).isoformat()}
        changed = admin.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": policy["version"], "rules": policy["rules"], "exceptions": [*policy["exceptions"], exception]})
        current_authored_version = changed["version"]
        admin.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": policy["version"], "rules": policy["rules"], "exceptions": policy["exceptions"]}, expected=409)
        check("policy stale version rejected", True)
        reanalysis_job = admin.request("POST", f"/api/v1/sbom-runs/{first_id}/analyses", expected=202)
        job_finished(reanalysis_job["jobId"])
        reanalyzed = detail(first_id)
        second_analysis = reanalyzed["analyses"][0]
        second_records = records(first_id, second_analysis["id"])
        report["evidence"].update({"reanalyzedRun": reanalyzed, "reanalyzedPolicies": second_records})
        check("expiring exact exception applied", any(row.get("exception", {}).get("id") == exception["id"] and row.get("suppressed") is True for row in second_records))
        historic = next(row for row in reanalyzed["analyses"] if row["id"] == first_analysis["id"])
        check("historic policy evidence immutable", historic["policyVersion"] == first_analysis["policyVersion"] and historic["policySnapshot"] == first_analysis["policySnapshot"] and records(first_id, first_analysis["id"]) == first_records)
        revision_comparison = admin.request("GET", "/api/v1/comparisons?" + urlencode({"baseRunId": first_id, "targetRunId": first_id, "baseAnalysisId": first_analysis["id"], "targetAnalysisId": second_analysis["id"]}))
        check("analysis revision policy comparison", revision_comparison["summary"]["policiesChanged"] >= 1)
        later_upload = admin.upload(fixed_bom, fields, idempotency_key=f"runtime-{unique}-comparison")
        report["evidence"]["uploads"].append(later_upload)
        job_finished(later_upload["jobId"])
        later = detail(later_upload["runId"])
        report["evidence"]["comparisonRun"] = later
        check("next SBOM round completed", later["roundNumber"] == first["roundNumber"] + 1 and later["state"] == "completed")
        round_comparison = admin.request("GET", "/api/v1/comparisons?" + urlencode({"baseRunId": first_id, "targetRunId": later["id"]}))
        check("round component comparison", round_comparison["summary"]["componentsChanged"] == 2)
        events = admin.request("GET", "/api/v1/audit-events?q=sbom_policy.update&size=100")
        check("policy audit trail", any(row.get("targetId") == str(changed["version"]) or row.get("action") == "sbom_policy.update" for row in events["items"]))
        csv = admin.request("GET", "/api/v1/audit-events?format=csv", as_bytes=True)
        check("audit CSV export", len(csv) > 100 and b"sbom_policy.update" in csv)
        viewer_password = secrets.token_urlsafe(24)
        hidden.append(viewer_password)
        viewer_name = f"native-viewer-{unique}"
        viewer_user = admin.request("POST", "/api/v1/users", data={"username": viewer_name, "password": viewer_password, "role": "viewer"}, expected=201)
        viewer = Client(args.base_url)
        viewer.login(viewer_name, viewer_password)
        hidden.append(viewer.csrf)
        check("viewer reads run and policies", viewer.request("GET", f"/api/v1/sbom-runs/{first_id}")["id"] == first_id and viewer.request("GET", "/api/v1/sbom-policies")["version"] == changed["version"])
        viewer.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": changed["version"], "rules": changed["rules"], "exceptions": changed["exceptions"]}, expected=403)
        check("viewer cannot modify policies", True)
        admin.request("PATCH", f"/api/v1/users/{viewer_user['id']}", data={"active": False})
        token = admin.request("POST", "/api/v1/api-tokens", data={"name": f"runtime-{unique}", "serviceId": service["id"]}, expected=201)
        hidden.append(token["token"])
        token_id = token["id"]
        integration = Client(args.base_url, bearer=token["token"]).request("GET", f"/api/v1/integrations/koda/runs/{first_id}")
        check("service token result integration", integration["run"]["id"] == first_id and integration["analysis"]["policyVersion"] == changed["version"])
        archived = admin.request("POST", f"/api/v1/sbom-runs/{later['id']}/archive", data={"reason": "실제 런타임 검증 완료 후 논리 보관"})
        check("logical archive preserves artifact", archived["state"] == "archived" and hashlib.sha256(admin.request("GET", f"/api/v1/sbom-runs/{later['id']}/artifact", as_bytes=True)).hexdigest() == later["sha256"])
        admin.request("POST", f"/api/v1/sbom-runs/{later['id']}/analyses", expected=409)
        check("archived run reanalysis rejected", True)
        report["evidence"].update({"initialRun": first, "initialPolicies": first_records, "initialFindings": findings,
                                   "reanalyzedRun": reanalyzed, "reanalyzedPolicies": second_records, "comparisonRun": later,
                                   "revisionComparison": revision_comparison, "roundComparison": round_comparison,
                                   "artifactSha256": first["sha256"], "policyException": exception})
        report["success"] = True
    except Exception as error:
        report["success"] = False
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        if token_id:
            try:
                admin.request("POST", f"/api/v1/api-tokens/{token_id}/revoke")
                report["tokenRevoked"] = True
            except Exception as error:
                report["success"] = False
                report["tokenRevocationError"] = str(error)
        if original_policy is not None and current_authored_version is not None:
            try:
                current = admin.request("GET", "/api/v1/sbom-policies")
                if current["version"] != current_authored_version:
                    raise VerificationError("Policy changed outside this verification; refusing to overwrite it")
                restored = admin.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": current["version"], "rules": original_policy["rules"], "exceptions": original_policy["exceptions"]})
                report["policyRestored"] = {"originalVersion": original_policy["version"], "restoredVersion": restored["version"], "sameRulesAndExceptions": restored["rules"] == original_policy["rules"] and restored["exceptions"] == original_policy["exceptions"]}
            except Exception as error:
                report["success"] = False
                report["policyRestoreError"] = str(error)
        report["finishedAt"] = datetime.now(UTC).isoformat()
    return report, hidden


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600, help="Maximum seconds per real worker job")
    args = parser.parse_args()
    if urlparse(args.base_url).scheme not in {"http", "https"}:
        parser.error("--base-url must be an HTTP(S) gateway URL")
    os.umask(0o077)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report, hidden = run(args)
    except Exception as error:
        report, hidden = {"success": False, "error": f"{type(error).__name__}: {error}"}, []
    serialized = json.dumps(report, ensure_ascii=False, indent=2)
    for secret in hidden:
        if secret:
            serialized = serialized.replace(secret, "[REDACTED]")
    output = args.output_dir / "runtime-report.json"
    output.write_text(serialized + "\n")
    print(f"Report: {output}")
    print(f"Result: {'PASS' if report.get('success') else 'FAIL'} ({len(report.get('checks', []))} checks)")
    if not report.get("success"):
        safe_report = json.loads(serialized)
        print(str(safe_report.get("error") or safe_report.get("policyRestoreError") or "See failure evidence"), file=sys.stderr)
    return 0 if report.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
