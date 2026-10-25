import base64
import copy
import gzip
import hashlib
import importlib.util
import json
import urllib.request
from urllib.parse import parse_qs, urlsplit
from datetime import datetime, timezone
from pathlib import Path

import pytest

from koda_tracker import offline_intelligence as parser

AT = datetime(2026, 10, 19, tzinfo=timezone.utc)
DATE = "2026-10-19"
PURL = "pkg:pypi/demo@1.0"
CVE = "CVE-2026-12345"
CPE = "cpe:2.3:a:example:demo:1.0:*:*:*:*:*:*:*"


def fixtures():
    return {
        "epss": f"#model_version:v2025.03.14,score_date:{DATE}T00:00:00+0000\ncve,epss,percentile\n{CVE},.8,.99\n".encode(),
        "vulnrichment": json.dumps({"cveMetadata": {"cveId": CVE}, "containers": {"adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"other": {"type": "ssvc", "content": {"version": "2.0.3", "timestamp": AT.isoformat(), "role": "CISA Coordinator", "options": [{"Exploitation": "Active"}, {"Automatable": "Yes"}, {"Technical Impact": "Total"}]}}}]}]}}).encode(),
        "csaf": json.dumps({"document": {"csaf_version": "2.0", "tracking": {"id": "vendor-2026-1", "current_release_date": AT.isoformat()}}, "product_tree": {"branches": [{"category": "product_name", "name": "Demo", "product": {"product_id": "demo-1", "name": "Demo 1.0", "product_identification_helper": {"purl": PURL}}}]}, "vulnerabilities": [{"cve": CVE, "product_status": {"known_affected": ["demo-1", "unresolved"]}, "remediations": [{"category": "vendor_fix", "details": "Upgrade 2.0", "product_ids": ["demo-1"]}]}]}).encode(),
        "vex": json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://vendor.test/vex/1", "timestamp": AT.isoformat(), "statements": [{"vulnerability": {"name": CVE}, "products": [{"@id": PURL}], "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}]}).encode(),
        "lifecycle": json.dumps({"schema_version": "1.2.1", "generated_at": AT.isoformat(), "last_modified": "2020-01-01T00:00:00Z", "result": {"name": "demo", "identifiers": [{"type": "purl", "id": "pkg:pypi/demo"}], "releases": [{"name": "1", "eolFrom": "2025-01-01", "isEol": True, "latest": {"name": "1.9", "date": "2024-10-01"}}]}}).encode(),
        "cpe-dictionary": json.dumps({"timestamp": AT.isoformat(), "products": [{"cpe": {"cpeNameId": "id-1", "cpeName": CPE, "deprecated": False, "titles": [{"title": "Demo 1.0"}]}}]}).encode(),
        "cpe-match": json.dumps({"timestamp": AT.isoformat(), "matchStrings": [{"matchString": {"criteria": CPE, "matchCriteriaId": "match-1", "status": "Active", "versionEndExcluding": "2.0", "matches": [{"cpeName": CPE, "cpeNameId": "id-1"}]}}]}).encode(),
        "cwe": f'<Weakness_Catalog Date="{DATE}"><Weaknesses><Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable"><Description>Output encoding issue</Description><Mapping_Notes><Usage>Allowed</Usage></Mapping_Notes></Weakness></Weaknesses><Categories><Category ID="1" Name="not a weakness"/></Categories></Weakness_Catalog>'.encode(),
        "spdx": json.dumps({"releaseDate": DATE, "licenses": [{"licenseId": "MIT", "name": "MIT License", "isOsiApproved": True}], "exceptions": [{"licenseExceptionId": "Classpath-exception-2.0", "name": "Classpath exception"}]}).encode(),
        "package-metadata": json.dumps({"format": "koda-package-metadata-v1", "exportedAt": AT.isoformat(), "items": [{"purl": PURL, "currentVersion": "1.0", "latestVersion": "2.0", "status": "fresh", "sourceKind": "offline_import", "fetchedAt": AT.isoformat(), "expiresAt": "2026-10-20T00:00:00Z", "sourceUrls": ["https://pypi.org/pypi/demo/json"]}]}).encode(),
        "ubuntu-oval": f'''<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><generator><timestamp>{AT.isoformat()}</timestamp></generator><definitions><definition id="oval:ubuntu:def:1"><metadata><affected family="unix"><platform>Ubuntu 22.04 LTS</platform></affected><reference source="CVE" ref_id="{CVE}"/></metadata><criteria operator="AND"><criterion test_ref="oval:ubuntu:tst:1"/></criteria></definition></definitions><tests><dpkginfo_test id="oval:ubuntu:tst:1" check="all"><object object_ref="oval:ubuntu:obj:1"/><state state_ref="oval:ubuntu:ste:1"/></dpkginfo_test></tests><objects><dpkginfo_object id="oval:ubuntu:obj:1"><name>demo</name></dpkginfo_object></objects><states><dpkginfo_state id="oval:ubuntu:ste:1"><evr datatype="evr_string" operation="less than">1:2.0-0ubuntu1</evr></dpkginfo_state></states></oval_definitions>'''.encode(),
    }


def document(tmp_path, *, inline=False):
    document = {"format": parser.FORMAT, "createdAt": AT.isoformat(), "datasets": {}}
    (tmp_path / "intelligence-sources").mkdir()
    for kind, raw in fixtures().items():
        digest = hashlib.sha256(raw).hexdigest()
        filename = f"intelligence-sources/{digest}.bin"
        (tmp_path / filename).write_bytes(raw)
        source = {"id": kind, "sourceUrl": "https://vendor.test/" + kind, "dataDate": DATE, "fetchedAt": AT.isoformat(), "sourceFile": filename}
        if inline:
            source["rawBase64"] = base64.b64encode(raw).decode()
        document["datasets"][kind] = parser.normalize_source(kind, raw, source)
    return document


def test_all_publisher_formats_have_exact_identifiers_and_original_proof(tmp_path):
    value = document(tmp_path)
    (tmp_path / "intelligence.json").write_text(json.dumps(value))
    result = parser.load_intelligence(tmp_path, at=AT)
    assert set(result["datasets"]) == parser.KINDS
    assert all(source["originalVerified"] and source["status"] == "fresh" for data in result["datasets"].values() for source in data["sources"])
    assert result["datasets"]["vulnrichment"]["records"][0]["exploitation"] == "active"
    assert result["datasets"]["vulnrichment"]["records"][0]["technicalImpact"] == "total"
    assert result["datasets"]["csaf"]["records"][0]["purl"] == PURL
    assert result["datasets"]["csaf"]["records"][1]["supported"] is False
    assert result["datasets"]["vex"]["records"][0]["status"] == "not_affected"
    assert result["datasets"]["lifecycle"]["sources"][0]["dataDate"] == DATE
    assert result["datasets"]["lifecycle"]["records"][0]["isEol"] is True
    assert result["datasets"]["cwe"]["records"] == [{"id": 79, "name": "XSS", "status": "Stable", "abstraction": "Base", "description": "Output encoding issue", "mappingUsage": ["Allowed"], "sourceId": "cwe"}]
    assert result["datasets"]["spdx"]["records"][1]["licenseType"] == "exception"
    oval = result["datasets"]["ubuntu-oval"]["records"][0]
    assert oval["supported"] and oval["tests"]["oval:ubuntu:tst:1"]["states"][0]["version"] == "1:2.0-0ubuntu1"


def test_canonical_json_cannot_forge_normalized_exploitation_or_hide_original(tmp_path):
    value = document(tmp_path, inline=True)
    assert parser.validate_document(value, at=AT)["datasets"]["epss"]["sources"][0]["originalVerified"]
    forged = copy.deepcopy(value)
    forged["datasets"]["vulnrichment"]["records"][0]["exploitation"] = "none"
    with pytest.raises(ValueError, match="differ"):
        parser.validate_document(forged, at=AT)
    del value["datasets"]["epss"]["sources"][0]["rawBase64"]
    with pytest.raises(ValueError, match="rawBase64"):
        parser.validate_document(value, at=AT)


def test_hash_metadata_future_and_symlink_changes_fail_before_use(tmp_path):
    value = document(tmp_path)
    source = value["datasets"]["epss"]["sources"][0]
    (tmp_path / source["sourceFile"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="size mismatch"):
        parser.validate_document(value, tmp_path, at=AT)
    raw = fixtures()["epss"]
    (tmp_path / source["sourceFile"]).write_bytes(raw)
    source["fetchedAt"] = "2030-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="future"):
        parser.validate_document(value, tmp_path, at=AT)
    source["fetchedAt"] = AT.isoformat()
    actual = tmp_path / source["sourceFile"]
    outside = tmp_path / "copy.bin"
    actual.replace(outside)
    actual.symlink_to(outside)
    with pytest.raises(ValueError, match="unsafe"):
        parser.validate_document(value, tmp_path, at=AT)


def test_oval_unsupported_variables_are_preserved_as_unknown():
    raw = fixtures()["ubuntu-oval"].replace(b"<name>demo</name>", b'<name var_ref="oval:ubuntu:var:1">demo</name>')
    value = parser.normalize_source("ubuntu-oval", raw, {"id": "oval", "dataDate": DATE})
    assert value["records"][0]["supported"] is False
    assert value["records"][0]["unsupportedReasons"]


def test_malformed_duplicate_json_entities_and_bombs_are_rejected(monkeypatch):
    for kind, raw in [("lifecycle", b'{"result":{},"result":{}}'), ("cwe", b'<!DOCTYPE x [<!ENTITY y "bad">]><Weakness_Catalog>&y;</Weakness_Catalog>')]:
        with pytest.raises(ValueError):
            parser.normalize_source(kind, raw, {"id": "bad", "dataDate": DATE})
    monkeypatch.setattr(parser, "MAX_FILE_BYTES", 100)
    with pytest.raises(ValueError, match="expanded"):
        parser.normalize_source("cwe", gzip.compress(b"x" * 101), {"id": "bad", "dataDate": DATE})


def test_source_status_tracks_stale_and_future_without_redating():
    source = {"dataDate": "2026-01-01", "maxAgeDays": 7}
    result = parser.source_status(source, at=AT)
    assert result["status"] == "stale" and result["dataDate"] == source["dataDate"]
    assert parser.source_status({**source, "dataDate": "2030-01-01"}, at=AT)["status"] == "future"


def test_collector_is_local_by_default_atomic_and_raw_sources_are_bundle_ready(tmp_path):
    spec = importlib.util.spec_from_file_location("collector", Path(__file__).parents[2] / "scripts/collect-offline-intelligence.py")
    collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
    raw = fixtures()["lifecycle"]
    (tmp_path / "source.json").write_bytes(raw)
    descriptor = {"sources": [{"id": "demo", "kind": "lifecycle", "path": "source.json", "sourceUrl": "https://endoflife.date/api/v1/products/demo/", "fetchedAt": AT.isoformat()}]}
    index = collector.collect(descriptor, tmp_path / "out", base=tmp_path, inline=True)
    result = parser.load_intelligence(index.parent, at=AT)
    assert result["datasets"]["lifecycle"]["records"][0]["product"] == "demo"
    assert parser.validate_document(json.loads(index.read_text()), at=AT)
    with pytest.raises(ValueError, match="exists"):
        collector.collect(descriptor, tmp_path / "out", base=tmp_path)
    descriptor["sources"][0].pop("path"); descriptor["sources"][0]["url"] = "https://endoflife.date/api/v1/products/demo/"
    with pytest.raises(ValueError, match="--fetch"):
        collector.collect(descriptor, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def test_collector_nvd_pagination_is_complete_bounded_and_records_actual_page_urls(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("collector_pages", Path(__file__).parents[2] / "scripts/collect-offline-intelligence.py")
    collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return AT.astimezone(tz) if tz else AT.replace(tzinfo=None)
    monkeypatch.setattr(collector, "datetime", FixedDatetime)
    urls, sleeps = [], []
    def fetch(url, allowed_hosts, *, trace=None):
        urls.append(url)
        trace.append(url)
        start = int(parse_qs(urlsplit(url).query).get("startIndex", [0])[0])
        return json.dumps({"timestamp": AT.isoformat(), "startIndex": start, "resultsPerPage": 1, "totalResults": 2,
                           "products": [{"cpe": {"cpeNameId": f"id-{start}", "cpeName": CPE.replace(":1.0:", f":{start+1}.0:")}}]}).encode()
    monkeypatch.setattr(collector, "fetch_url", fetch)
    monkeypatch.setattr(collector.time, "sleep", sleeps.append)
    descriptor = {"sources": [{"id": "cpe", "kind": "cpe-dictionary", "url": "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=demo", "paginate": True, "maxPages": 2}]}
    index = collector.collect(descriptor, tmp_path / "pages", fetch=True)
    result = parser.load_intelligence(index.parent, at=AT)
    assert len(result["datasets"]["cpe-dictionary"]["records"]) == 2 and len(urls) == 2
    assert "startIndex=1" in urls[1] and sleeps == [6.5]
    assert result["datasets"]["cpe-dictionary"]["sources"][1]["sourceUrl"] == urls[1]
    descriptor["sources"][0]["maxPages"] = 1
    with pytest.raises(ValueError, match="incomplete"):
        collector.collect(descriptor, tmp_path / "incomplete", fetch=True)
    assert not (tmp_path / "incomplete").exists()


def test_collector_redirects_validate_every_target_and_never_follow_http_or_unapproved_host():
    spec = importlib.util.spec_from_file_location("collector_redirects", Path(__file__).parents[2] / "scripts/collect-offline-intelligence.py")
    collector = importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
    initial = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    trace = [initial]
    handler = collector.ApprovedRedirect(collector.HOSTS, trace)
    request = urllib.request.Request(initial)
    accepted = handler.redirect_request(request, None, 302, "Found", {}, "/epss_scores-2026-10-19.csv.gz")
    assert accepted.full_url.endswith("epss_scores-2026-10-19.csv.gz") and len(trace) == 2
    for target in ("http://epss.empiricalsecurity.com/scores.gz", "https://evil.example/scores.gz", "https://raw.githubusercontent.com/attacker/data/main/scores.json"):
        with pytest.raises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, target)
    trace[:] = [initial] * 6
    with pytest.raises(ValueError, match="limit"):
        handler.redirect_request(request, None, 302, "Found", {}, initial)


@pytest.mark.parametrize('field,value', [('schemaVersion', 'forged-schema'), ('sourceVersion', 'forged-model'), ('dateBasis', 'operator')])
def test_source_schema_model_and_date_basis_are_bound_to_original(tmp_path, field, value):
    payload = document(tmp_path, inline=True)
    payload['datasets']['epss']['sources'][0][field] = value
    with pytest.raises(ValueError, match=f'source {field} differs'):
        parser.validate_document(payload, at=AT)
