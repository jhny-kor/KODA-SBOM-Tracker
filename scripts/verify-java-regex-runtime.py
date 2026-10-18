#!/usr/bin/env python3
"""Sample-only acceptance for source 4.13.4 Java regex policies on real Docker.

Use a disposable source containing no operating data. Private API credentials
come from files and are never copied into the report. --seed-only prepares the
source fixture without changing KODA policies or importing anything.
"""
from __future__ import annotations

import argparse
import copy
from datetime import UTC, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time
import uuid

_spec = importlib.util.spec_from_file_location("native", Path(__file__).with_name("verify-native-runtime.py"))
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)

SOURCE_REQUEST = """import json,sys,httpx
x=json.load(sys.stdin);a=x['auth'];c=httpx.Client(headers={'X-Api-Key':a['apiKey']},timeout=30,trust_env=False,follow_redirects=False)
if x.get('bom') is not None:r=c.post(a['baseUrl']+'/api/v1/bom',data={'project':x['project']},files={'bom':('sample.cdx.json',json.dumps(x['bom']).encode(),'application/json')})
else:r=c.request(x['method'],a['baseUrl']+'/api/v1'+x['path'],json=x.get('body'))
print(json.dumps({'status':r.status_code,'data':r.json() if r.content and r.headers.get('content-type','').startswith('application/json') else None}))
"""


def runtime_failure_probe(api_container: str, run_id: str) -> dict:
    """Run the real scanner with an unavailable matcher in this child only."""
    code = """import json,sys
from koda_tracker.db import SessionLocal
from koda_tracker.models import SbomRun
from koda_tracker.services import analyze_offline
x=json.load(sys.stdin)
with SessionLocal() as db:
 run=db.get(SbomRun,x['runId']);revision=analyze_offline(db,run);db.commit()
 print(json.dumps({'sequence':revision.sequence,'analysisState':revision.state,'policyState':revision.policy_state,'policyError':revision.policy_error,'metrics':revision.metrics,'resultCount':len(revision.policies or [])}))
"""
    result = subprocess.run(["docker", "exec", "-i", "-e", "KODA_JAVA_BINARY=/nonexistent-java-for-acceptance", api_container, "python", "-c", code], input=json.dumps({"runId": run_id}), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--source-auth-file", type=Path, required=True)
    parser.add_argument("--fixture-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:18088")
    parser.add_argument("--api-container", default="koda-native-verify-20261017-portal-api")
    parser.add_argument("--worker-container", default="koda-native-verify-20261017-portal-worker")
    parser.add_argument("--source-container", default="koda-java-regex-source4")
    parser.add_argument("--seed-only", action="store_true")
    args = parser.parse_args()
    auth = json.loads(args.source_auth_file.read_text())

    def source(method, path, body=None, **extra):
        result = subprocess.run(
            ["docker", "exec", "-i", args.api_container, "python", "-c", SOURCE_REQUEST],
            input=json.dumps({"auth": auth, "method": method, "path": path, "body": body, **extra}),
            text=True, capture_output=True, check=True,
        )
        payload = json.loads(result.stdout)
        if payload["status"] >= 300:
            raise RuntimeError(f"sample source {method} {path}: HTTP {payload['status']}")
        return payload["data"]

    def wait(predicate, label, timeout=240):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(1)
        raise RuntimeError(label + " timeout")

    if args.fixture_file.exists():
        fixture = json.loads(args.fixture_file.read_text())
    else:
        name = "KODA-java4-" + uuid.uuid4().hex[:8]
        project = source("PUT", "/project", {"name": name, "version": "1", "active": True, "classifier": "APPLICATION"})
        bom = json.loads(native.make_bom("2.14.1", "4.17.20"))
        log4j = next(c for c in bom["components"] if c["name"] == "log4j-core")
        log4j["group"] = "org.apache.logging.log4j"
        log4j["cpe"] = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        synthetic = {"type": "library", "name": "alpha-alpha", "group": "org.example", "version": "1.0", "bom-ref": "alpha-alpha", "purl": "pkg:generic/alpha-alpha@1.0", "licenses": [{"license": {"id": "MIT"}}], "swid": {"tagId": "com.example.한국.repeat-repeat", "name": "alpha-alpha", "version": "1.0"}}
        bom["components"].append(synthetic)
        source("POST", "/bom", bom=bom, project=project["uuid"])
        wait(lambda: len(source("GET", "/component/project/" + project["uuid"])) == 3, "source sample BOM")
        # Each expected answer refers to one named component. NO_MATCH policies
        # may legitimately match other components with a different/missing field.
        definitions = [
            ("lookbehind", "PACKAGE_URL", "MATCHES", r"(?<=org\.apache\.logging\.)log4j/log4j-core@2\.14\.1$", "log4j-core", True),
            ("negative-lookbehind", "PACKAGE_URL", "MATCHES", r"(?<!forbidden/)log4j-core@2\.14\.1$", "log4j-core", True),
            ("numbered-backref", "PACKAGE_URL", "MATCHES", r"^pkg:generic/(alpha)-\1@1\.0$", "alpha-alpha", True),
            ("named-backref", "SWID_TAGID", "MATCHES", r"^com\.example\.한국\.(?<part>repeat)-\k<part>$", "alpha-alpha", True),
            ("class-intersection", "CPE", "MATCHES", r"[a-z&&[^x]]+:log4j:2\.14\.1:*", "log4j-core", True),
            ("class-subtraction", "SWID_TAGID", "MATCHES", r"^com\.example\.한국\.[a-z&&[^xyz]]+-[a-z&&[^xyz]]+$", "alpha-alpha", True),
            ("unicode", "SWID_TAGID", "MATCHES", r"\p{IsHangul}+", "alpha-alpha", True),
            ("atomic", "PACKAGE_URL", "MATCHES", r"^pkg:maven/(?>org\.apache\.logging\.log4j)/log4j-core@2\.14\.1$", "log4j-core", True),
            ("possessive", "PACKAGE_URL", "MATCHES", r"^pkg:maven/[^/]++/log4j-core@2\.14\.1$", "log4j-core", True),
            ("quoted", "PACKAGE_URL", "MATCHES", r"\Qlog4j-core@2.14.1\E$", "log4j-core", True),
            ("flags", "PACKAGE_URL", "MATCHES", r"(?i)^PKG:MAVEN/ORG\.APACHE\.LOGGING\.LOG4J/LOG4J-CORE@2\.14\.1$", "log4j-core", True),
            ("fullmatch-negative", "PACKAGE_URL", "MATCHES", r"^log4j-core$", "log4j-core", False),
            ("wildcard", "PACKAGE_URL", "MATCHES", "*log4j-core*", "log4j-core", True),
            ("purl-no-match", "PACKAGE_URL", "NO_MATCH", r"(?<=log4j-)core@2\.14\.1$", "log4j-core", False),
            ("cpe-no-match", "CPE", "NO_MATCH", r"(?<=apache:)log4j:", "log4j-core", False),
            ("swid-no-match", "SWID_TAGID", "NO_MATCH", r"(?<part>repeat)-\k<part>$", "alpha-alpha", False),
            ("coordinate-match", "COORDINATES", "MATCHES", json.dumps({"group": r"^org\.(?>apache)\.logging\.log4j$", "name": r"(?<=log4j-)core$", "version": r"2\.14\.1"}), "log4j-core", True),
            ("coordinate-no-match-all", "COORDINATES", "NO_MATCH", json.dumps({"group": "^different$", "name": "^other$", "version": "^99$"}), "log4j-core", True),
            ("coordinate-no-match-one", "COORDINATES", "NO_MATCH", json.dumps({"group": r"^org\.apache\.logging\.log4j$", "name": "^other$", "version": "^99$"}), "log4j-core", False),
        ]
        cases = []
        for label, subject, operator, value, component, expected in definitions:
            policy = source("PUT", "/policy", {"name": name + "-" + label, "operator": "ALL", "violationState": "FAIL"})
            source("PUT", "/policy/" + policy["uuid"] + "/condition", {"subject": subject, "operator": operator, "value": value})
            source("POST", "/policy/" + policy["uuid"] + "/project/" + project["uuid"])
            cases.append({"label": label, "policyId": policy["uuid"], "policyName": name + "-" + label, "component": component, "expected": expected})
        fixture = {"name": name, "projectId": project["uuid"], "bom": bom, "cases": cases, "sourceVersion": "4.13.4"}
        args.fixture_file.parent.mkdir(parents=True, exist_ok=True)
        args.fixture_file.write_text(json.dumps(fixture, ensure_ascii=False, indent=2))
    if args.seed_only:
        print(f"Prepared source4 sample: {len(fixture['cases'])} policy cases, 3 components", flush=True)
        return

    env = native.dotenv(args.env_file)
    client = native.Client(args.base_url)
    client.login(env.get("TRACKER_BOOTSTRAP_ADMIN_USERNAME", "admin"), env["TRACKER_BOOTSTRAP_ADMIN_PASSWORD"])
    original = client.request("GET", "/api/v1/sbom-policies")
    report = {"startedAt": datetime.now(UTC).isoformat(), "checks": [], "evidence": {"sourceVersion": fixture["sourceVersion"], "projectId": fixture["projectId"], "sampleCases": fixture["cases"]}}
    source_stopped = False

    def check(name, condition, evidence=None):
        if not condition:
            raise RuntimeError(name + ": " + str(evidence))
        report["checks"].append({"name": name, "passed": True})
        if evidence is not None:
            report["evidence"][name] = evidence
        print("PASS", name, flush=True)

    def reanalyze(run_id):
        job = client.request("POST", f"/api/v1/sbom-runs/{run_id}/analyses", expected=202)
        result = wait(lambda: (j if (j := client.request("GET", "/api/v1/jobs/" + job["jobId"]))["state"] in ("completed", "failed") else None), "real Grype analysis")
        check("Grype worker completed " + job["jobId"], result["state"] == "completed")
        return client.request("GET", "/api/v1/sbom-runs/" + run_id)

    try:
        check("standalone native deployment", client.request("GET", "/api/v1/dependency-track/status")["enabled"] is False)
        source("POST", "/bom", bom=fixture["bom"], project=fixture["projectId"])
        def source_answers():
            violations = source("GET", "/violation/project/" + fixture["projectId"] + "?suppressed=true&pageSize=100")
            answers = []
            for case in fixture["cases"]:
                matched = any((v.get("policyCondition", {}).get("policy", {}).get("uuid") == case["policyId"] or v.get("policy", {}).get("uuid") == case["policyId"]) and v.get("component", {}).get("name") == case["component"] for v in violations)
                answers.append(matched == case["expected"])
            return violations if all(answers) and violations else None
        source_rows = wait(source_answers, "source4 actual policy evaluation", 300)
        check("actual source4 policy results match all sample expectations", True, source_rows)
        request = {"baseUrl": auth["baseUrl"], "apiKey": auth["apiKey"], "allowedOrigins": [auth["baseUrl"]], "projectUuids": [fixture["projectId"]]}
        staged = client.request("POST", "/api/v1/legacy-migrations/export-stage", data=request, expected=201)
        check("real source4 API Java conditions all convert", staged["report"]["canApply"] and staged["report"]["counts"]["convertedPolicies"] == len(fixture["cases"]), staged["report"])
        bundle = client.request("GET", "/api/v1/legacy-migrations/" + staged["id"] + "/bundle")
        check("exporter observes actual source4 version", bundle["source"]["version"] == "4.13.4")
        invalid = copy.deepcopy(bundle)
        invalid_condition = next(condition for policy in invalid["policies"] for condition in policy["policyConditions"] if condition["subject"] == "PACKAGE_URL")
        invalid_condition["value"] = "(?<broken"
        blocked = client.request("POST", "/api/v1/legacy-migrations/stage", data={"bundle": invalid}, expected=201)
        check("invalid Java syntax blocks whole staging", not blocked["report"]["canApply"] and any("Java 정규식 문법" in blocker["reason"] for blocker in blocked["report"]["blockers"]), blocked["report"]["blockers"])
        current = client.request("GET", "/api/v1/sbom-policies")
        applied = client.request("POST", "/api/v1/legacy-migrations/" + staged["id"] + "/apply", data={"expectedDigest": staged["digest"], "expectedPolicyVersion": current["version"], "trustSourceReviews": False})
        check("real source4 policies apply atomically", applied["state"] == "applied")
        run_id = applied["result"]["runIds"][0]
        report["evidence"]["runId"] = run_id
        subprocess.run(["docker", "stop", args.source_container], capture_output=True, check=True)
        source_stopped = True
        detail = reanalyze(run_id)
        check("real Grype DB completes with source4 stopped", detail["analyses"][0]["toolVersion"] == "0.109.1" and detail["policyState"] == "completed" and detail["vulnerabilityCount"] >= 12, {"vulnerabilities": detail["vulnerabilityCount"], "dataSources": detail["analysisDataSources"], "metrics": detail["analysisMetrics"]})
        rows = client.request("GET", f"/api/v1/sbom-runs/{run_id}/policy-violations?size=100")["items"]
        check("Java regex evidence is complete", not any(row["type"] == "data_unavailable" for row in rows), rows)
        runtimes = detail["analysisMetrics"].get("policyCompatibilityRuntimes", [])
        check("Java21 compatibility runtime is preserved in analysis evidence", any(r.get("runtime") == "java.util.regex.Pattern" and r.get("javaMajor") == 21 and r.get("isolated") for r in runtimes), runtimes)
        policy_names = {case["policyId"]: case["policyName"] for case in fixture["cases"]}
        source_pairs = {(policy_names[v["policyCondition"]["policy"]["uuid"]], v["component"]["name"]) for v in source_rows}
        component_names = {component["name"] for component in fixture["bom"]["components"]}
        native_pairs = {(row["policyName"], next(name for name in component_names if name in row["component"])) for row in rows if row["policyName"] in policy_names.values()}
        check("complete source4 and native policy-component result sets agree", native_pairs == source_pairs, {"source": sorted(source_pairs), "native": sorted(native_pairs)})
        for case in fixture["cases"]:
            actual = any(row["policyName"] == case["policyName"] and (row["component"] == case["component"] or case["component"] in row["component"]) for row in rows)
            check("native Java policy " + case["label"], actual == case["expected"], {"expected": case["expected"], "actual": actual})
        failure = runtime_failure_probe(args.api_container, run_id)
        check("missing Java runtime yields explicit failed policy rather than pass", failure["analysisState"] == "completed" and failure["policyState"] == "failed" and failure["metrics"].get("policyStatus") == "error" and failure["resultCount"] == 0, failure)
        detail = reanalyze(run_id)
        check("normal worker recovers after isolated Java failure", detail["policyState"] == "completed" and detail["analysisMetrics"].get("policyCompatibilityRuntimes"))
        sha = hashlib.sha256(client.request("GET", f"/api/v1/sbom-runs/{run_id}/artifact", as_bytes=True)).hexdigest()
        snapshot = detail["analyses"][0]["policySnapshot"]
        sequence = detail["analyses"][0]["sequence"]
        later = reanalyze(run_id)
        check("new Java analysis preserves previous immutable snapshot", later["analyses"][0]["sequence"] == sequence + 1 and later["analyses"][1]["policySnapshot"] == snapshot)
        subprocess.run(["docker", "restart", args.worker_container], check=True, capture_output=True)
        persisted = client.request("GET", "/api/v1/sbom-runs/" + run_id)
        check("worker restart preserves Java results and original artifact", persisted["analyses"] == later["analyses"] and hashlib.sha256(client.request("GET", f"/api/v1/sbom-runs/{run_id}/artifact", as_bytes=True)).hexdigest() == sha)
        report["evidence"]["sourceStopped"] = source_stopped
    finally:
        current = client.request("GET", "/api/v1/sbom-policies")
        client.request("PUT", "/api/v1/sbom-policies", data={"expectedVersion": current["version"], "rules": original["rules"], "exceptions": original["exceptions"]})
        if not source_stopped:
            subprocess.run(["docker", "stop", args.source_container], capture_output=True)
        report["finishedAt"] = datetime.now(UTC).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print("PASS", len(report["checks"]), "real source4 Java regex checks", flush=True)


if __name__ == "__main__":
    main()
