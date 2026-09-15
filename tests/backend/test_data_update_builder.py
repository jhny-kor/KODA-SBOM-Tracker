import importlib.util
import json
from pathlib import Path

import pytest

from koda_tracker.data_updates import DataUpdateError, validate_package


def test_external_builder_produces_typed_upload_and_refuses_overwrite(tmp_path):
    spec = importlib.util.spec_from_file_location('data_builder', Path(__file__).parents[2] / 'scripts/build-data-update.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'nvd.json').write_text(json.dumps({'aliases': {'CVE-2026-1234': 'CVE-2026-1234'}, 'vulnerabilities': {'CVE-2026-1234': {'id': 'CVE-2026-1234'}}}))
    (source / 'kev.json').write_text('{"vulnerabilities": [], "dateReleased": "2026-09-14"}')
    output = tmp_path / 'update.tar.gz'
    builder.build('vuln-data', source, output, 'test-20260914', '2026-09-14')
    package = validate_package(output, 'vuln-data')
    assert package.version == 'test-20260914'
    assert package.metadata['KEV_DATASET_DATE'] == '2026-09-14'
    assert output.with_suffix('.gz.sha256').is_file()
    with pytest.raises(DataUpdateError):
        validate_package(output, 'grype-db')
    with pytest.raises(ValueError, match='already exists'):
        builder.build('vuln-data', source, output, 'test-20260914', '2026-09-14')
