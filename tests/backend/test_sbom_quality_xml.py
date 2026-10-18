"""XML diagnostic inputs must retain the same evidence as CycloneDX JSON."""
from __future__ import annotations

import json

import pytest

from koda_tracker.sbom import parse_sbom_file


def parse_file(tmp_path, content, suffix):
    path = tmp_path / ("bom." + suffix)
    path.write_bytes(content)
    return parse_sbom_file(path)[0]


def test_xml_quality_provenance_and_nested_evidence_match_json(tmp_path):
    raw = b'''<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="3" serialNumber="urn:uuid:00000000-0000-4000-8000-000000000001">
      <metadata><timestamp>2026-10-18T00:00:00Z</timestamp>
        <tools><components><component type="application" bom-ref="generator"><name>sbom-tool</name><version>1.2.3</version></component></components></tools>
        <authors><author><name>Build Team</name><email>build@example.test</email></author></authors>
        <supplier><name>Example</name><url>https://example.test</url><contact><name>Maintainer</name></contact></supplier>
        <manufacturer><name>Factory</name></manufacturer>
        <component type="application" bom-ref="app"><name>application</name><version>1.0</version><purl>pkg:generic/application@1.0</purl><hashes><hash alg="SHA-256">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</hash></hashes></component>
      </metadata>
      <components><component type="library" bom-ref="parent"><name>parent</name><version>1</version><purl>pkg:generic/parent@1</purl><supplier><name>Library Team</name></supplier>
        <components><component type="library" bom-ref="child"><name>child</name><version>2</version><cpe>cpe:2.3:a:example:child:2:*:*:*:*:*:*:*</cpe>
          <swid tagId="child-2" name="child" version="2" tagVersion="1" patch="false"><text content-type="text/xml" encoding="base64">eA==</text><url>https://example.test/swid</url></swid>
          <hashes><hash alg="SHA-256">bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb</hash><hash alg="SHA-256">cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc</hash></hashes>
          <licenses><expression>MIT OR Apache-2.0</expression><license><name>Custom License</name><url>https://example.test/license</url></license></licenses>
          <properties><property name="build:source">source.tar.gz</property></properties>
        </component></components>
      </component></components>
      <dependencies><dependency ref="app"><dependency ref="parent"/></dependency><dependency ref="parent"><dependency ref="child"/></dependency><dependency ref="child"/></dependencies>
    </bom>'''
    expected = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 3,
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "metadata": {
            "timestamp": "2026-10-18T00:00:00Z",
            "tools": {"components": [{"type": "application", "bom-ref": "generator", "name": "sbom-tool", "version": "1.2.3"}]},
            "authors": [{"name": "Build Team", "email": "build@example.test"}],
            "supplier": {"name": "Example", "url": ["https://example.test"], "contact": [{"name": "Maintainer"}]},
            "manufacturer": {"name": "Factory"},
            "component": {"type": "application", "bom-ref": "app", "name": "application", "version": "1.0", "purl": "pkg:generic/application@1.0", "hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
        },
        "components": [{"type": "library", "bom-ref": "parent", "name": "parent", "version": "1", "purl": "pkg:generic/parent@1", "supplier": {"name": "Library Team"}, "components": [{
            "type": "library", "bom-ref": "child", "name": "child", "version": "2", "cpe": "cpe:2.3:a:example:child:2:*:*:*:*:*:*:*",
            "swid": {"tagId": "child-2", "name": "child", "version": "2", "tagVersion": 1, "patch": False, "text": {"contentType": "text/xml", "encoding": "base64", "content": "eA=="}, "url": "https://example.test/swid"},
            "hashes": [{"alg": "SHA-256", "content": "b" * 64}, {"alg": "SHA-256", "content": "c" * 64}],
            "licenses": [{"expression": "MIT OR Apache-2.0"}, {"license": {"name": "Custom License", "url": "https://example.test/license"}}],
            "properties": [{"name": "build:source", "value": "source.tar.gz"}],
        }]}],
        "dependencies": [{"ref": "app", "dependsOn": ["parent"]}, {"ref": "parent", "dependsOn": ["child"]}, {"ref": "child", "dependsOn": []}],
    }
    actual = parse_file(tmp_path, raw, "xml")
    assert actual == parse_file(tmp_path, json.dumps(expected).encode(), "json")


def test_xml_legacy_tools_and_empty_provenance_are_not_filled_in(tmp_path):
    raw = b'''<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1"><metadata><timestamp/><tools><tool><vendor>Vendor</vendor><name>Scanner</name><version>2</version><hashes><hash alg="SHA-256">bad</hash></hashes></tool></tools><manufacture><name>Old spelling</name></manufacture></metadata><components><component type="library"><name>demo</name></component></components></bom>'''
    actual = parse_file(tmp_path, raw, "xml")
    assert actual["metadata"] == {"timestamp": "", "tools": [{"vendor": "Vendor", "name": "Scanner", "version": "2", "hashes": [{"alg": "SHA-256", "content": "bad"}]}], "manufacture": {"name": "Old spelling"}}
    assert "version" not in actual["components"][0]
    assert "serialNumber" not in actual


@pytest.mark.parametrize("attribute", ["tagVersion=\"not-an-integer\"", "patch=\"maybe\""])
def test_xml_invalid_swid_values_remain_visible_for_diagnostics(tmp_path, attribute):
    actual = parse_file(tmp_path, ('<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component type="library"><name>x</name><swid tagId="x" name="x" ' + attribute + '/></component></components></bom>').encode(), "xml")
    assert next(value for key, value in actual["components"][0]["swid"].items() if key in {"tagVersion", "patch"}) in {"not-an-integer", "maybe"}
