"""Store large CycloneDX documents as independently compressed ordered records."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import zlib
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session

from .asset_evidence import AssetPropertyValidator
from .models import SbomDocumentRecord
from .oracle_evidence import ORACLE_COMPONENT_REF
from .sbom import MAX_UPLOAD_DOCUMENT_BYTES, SbomValidationError, validate_file_with_cyclonedx_cli

CYCLONEDX_JSON = "application/vnd.cyclonedx+json"
LARGE_DOCUMENT_THRESHOLD = MAX_UPLOAD_DOCUMENT_BYTES
_MAX_PROJECTION_BYTES = 48 * 1024**2
_MAX_FRAGMENT_BYTES = 48 * 1024**2
_MAX_INSERT_BYTES = 8 * 1024**2
_MAX_DEPENDENCIES = 100_000
_MAX_EDGES = 500_000
_COMPONENT_FIELDS = (
    "bom-ref", "type", "group", "name", "version", "purl", "cpe", "swid", "hashes", "licenses",
    "supplier", "author", "publisher", "legacyLicense", "legacyLiteralFields", "isInternal",
)
_STANDARD_PROPERTIES = {"koda:latestVersion", "koda:publishedAt", "koda:ageDays", "koda:versionDistance"}


def _encode(record: object, *, canonical: bool = False) -> bytes:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False, sort_keys=canonical).encode()


def _analysis_component(component: dict) -> dict:
    result = {key: component[key] for key in _COMPONENT_FIELDS if key in component}
    ref = component.get("bom-ref")
    oracle = isinstance(ref, str) and ORACLE_COMPONENT_REF.fullmatch(ref) is not None
    if oracle and "evidence" in component:
        result["evidence"] = component["evidence"]
    if "components" in component:
        result["components"] = [_analysis_component(child) for child in component["components"]]
    return result


def _validate_db_fields(node: dict) -> None:
    for key, maximum in (("type", 64), ("group", 512), ("name", 512), ("version", 255),
                         ("purl", 4096), ("bom-ref", 4096)):
        value = node.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > maximum or "\x00" in value):
            raise SbomValidationError(f"SBOM 구성요소의 {key} 값이 올바르지 않습니다")


def _project_properties(component: dict, result: dict) -> None:
    """Keep lightweight policy and evidence fields in the common read model."""
    ref = component.get("bom-ref")
    oracle = isinstance(ref, str) and ORACLE_COMPONENT_REF.fullmatch(ref) is not None
    properties = component.get("properties") or []
    if not isinstance(properties, list) or any(not isinstance(prop, dict) for prop in properties):
        raise SbomValidationError("SBOM 구성요소 properties는 객체 배열이어야 합니다")
    relevant = []
    used = 0
    for prop in properties:
        key = prop.get("name")
        if not isinstance(key, str):
            raise SbomValidationError("SBOM 구성요소 property의 이름이 올바르지 않습니다")
        if key in _STANDARD_PROPERTIES or key.startswith("koda:asset:") or (
            oracle and (key in {"koda:spdx:package", "syft:package:foundBy"} or key.startswith("syft:metadata:"))
        ):
            relevant.append(prop)
            continue
        value = prop.get("value", "")
        if len(key) + len(value) > 256 - used:
            continue
        size = len(_encode(prop))
        if size <= 256 - used:
            relevant.append(prop)
            used += size
    if relevant:
        result["properties"] = relevant


class LargeSbom:
    def __init__(self, spool: sqlite3.Connection, max_components: int, unpacked_bytes: int):
        self.spool = spool
        self.max_components = max_components
        self.unpacked_bytes = unpacked_bytes
        self.component_count = 0
        self.projection_bytes = 0
        self.components: list[dict] = []
        self.dependencies: list[dict] = []
        self.edge_count = 0
        self.asset_properties = AssetPropertyValidator()
        self.metadata: dict = {}

    def _budget(self, size: int) -> None:
        self.projection_bytes += size
        if self.projection_bytes > _MAX_PROJECTION_BYTES:
            raise SbomValidationError(
                "대용량 SBOM의 구성요소 요약과 의존 관계가 메모리 처리 한도를 초과했습니다"
            )

    def _project(self, record: dict, projection: dict) -> None:
        _validate_db_fields(record)
        self.component_count += 1
        if self.component_count > self.max_components:
            raise SbomValidationError(f"SBOM 구성요소 수가 제한({self.max_components:,})을 초과했습니다")
        self.asset_properties.observe(record)
        _project_properties(record, projection)
        for child, projected in zip(record.get("components", []), projection.get("components", []), strict=True):
            self._project(child, projected)

    def add_component(self, record: dict) -> None:
        projection = _analysis_component(record)
        self._project(record, projection)
        self._budget(len(_encode(projection)) + 1)
        self._store("components", len(self.components), record)
        self.components.append(projection)

    def add_dependency(self, record: dict) -> None:
        self.edge_count += len(record.get("dependsOn", [])) + len(record.get("provides", []))
        if len(self.dependencies) >= _MAX_DEPENDENCIES or self.edge_count > _MAX_EDGES:
            raise SbomValidationError("대용량 SBOM의 의존 관계 또는 참조 수가 처리 한도를 초과했습니다")
        projection = {key: record[key] for key in ("ref", "dependsOn", "provides") if key in record}
        self._budget(len(_encode(projection)) + 1)
        self._store("dependencies", len(self.dependencies), record)
        self.dependencies.append(projection)

    def _store(self, section: str, ordinal: int, record: dict) -> None:
        try:
            raw = _encode(record, canonical=True)
            data = zlib.compress(raw, level=1)
            self.spool.execute("INSERT INTO records VALUES (?, ?, ?, ?)",
                               (section, ordinal, hashlib.sha256(raw).digest(), data))
        except sqlite3.IntegrityError as exc:
            raise SbomValidationError(f"대용량 SBOM {section} 배열에 중복 항목이 있습니다") from exc
        except (UnicodeError, ValueError) as exc:
            raise SbomValidationError("대용량 SBOM에 저장할 수 없는 JSON 값이 있습니다") from exc

    @property
    def compatibility_view(self) -> dict:
        return {
            **self.metadata, "components": self.components, "dependencies": self.dependencies,
            "_trackerUnpackedBytes": self.unpacked_bytes,
        }

    def _rows(self, section: str):
        return self.spool.execute(
            "SELECT ordinal, content FROM records WHERE section = ? ORDER BY ordinal", (section,)
        )

    def persist(self, db: Session, run_id: str) -> None:
        statement = insert(SbomDocumentRecord)
        batch = []
        batch_size = 0
        for section in ("components", "dependencies"):
            for ordinal, content in self._rows(section):
                if batch and (len(batch) >= 256 or batch_size + len(content) > _MAX_INSERT_BYTES):
                    db.execute(statement, batch)
                    batch.clear()
                    batch_size = 0
                batch.append(dict(run_id=run_id, section=section, ordinal=ordinal, compressed_json=content))
                batch_size += len(content)
        if batch:
            db.execute(statement, batch)

    def validate_schema(self, root: Path, binary: str) -> None:
        if not binary:
            return
        # Validate the metadata and every original component/relationship,
        # using the same pinned schema validator on bounded documents.
        # Cross-record reference resolution is performed by Tracker quality.
        fragment = root / "fragment.cdx.json"
        header = _encode(self.metadata)
        def validate_cdx() -> None:
            validate_file_with_cyclonedx_cli(
                fragment, binary, input_format="json", parsed_document=({}, CYCLONEDX_JSON)
            )

        fragment.write_bytes(header)
        validate_cdx()
        for section in ("components", "dependencies"):
            prefix = header[:-1] + b"," + _encode(section) + b":["
            with fragment.open("wb") as output:
                size = 0
                for _, compressed in self._rows(section):
                    data = zlib.decompress(compressed)
                    if size and size + len(data) > _MAX_FRAGMENT_BYTES:
                        output.write(b"]}")
                        output.flush()
                        validate_cdx()
                        output.seek(0)
                        output.truncate()
                        size = 0
                    output.write(b"," if size else prefix)
                    output.write(data)
                    size += len(data) + 1
                if size:
                    output.write(b"]}")
                    output.flush()
                    validate_cdx()


@contextmanager
def stage_large_sbom(path: Path, spool: Path, *, max_components: int, binary: str) -> Iterator[LargeSbom]:
    from .large_sbom_reader import read_large_cyclonedx

    with tempfile.TemporaryDirectory(prefix=".koda-large-sbom-", dir=spool) as output:
        root = Path(output)
        with closing(sqlite3.connect(root / "records.sqlite3")) as staging:
            staging.execute("PRAGMA journal_mode = OFF")
            staging.execute(
                "CREATE TABLE records (section TEXT, ordinal INTEGER, digest BLOB, content BLOB, "
                "PRIMARY KEY (section, ordinal), UNIQUE (section, digest)) WITHOUT ROWID"
            )
            document = LargeSbom(staging, max_components, path.stat().st_size)
            try:
                document.metadata = read_large_cyclonedx(path, document.add_component, document.add_dependency)
                document.asset_properties.finish()
                document._budget(len(_encode(document.metadata)))
            except (UnicodeError, ValueError) as exc:
                if isinstance(exc, SbomValidationError):
                    raise
                raise SbomValidationError("대용량 SBOM 문서가 올바르지 않습니다") from exc
            serial = document.metadata.get("serialNumber")
            if serial is not None and (not isinstance(serial, str) or len(serial) > 255 or "\x00" in serial):
                raise SbomValidationError("SBOM 문서 식별자가 올바르지 않습니다")
            document.validate_schema(root, binary)
            yield document


def iter_large_records(db: Session, run_id: str, section: str) -> Iterator[dict]:
    after = -1
    # Keyset reads cap driver buffering and permit scans between requests.
    while True:
        rows = db.execute(
            select(SbomDocumentRecord.ordinal, SbomDocumentRecord.compressed_json)
            .where(SbomDocumentRecord.run_id == run_id, SbomDocumentRecord.section == section,
                   SbomDocumentRecord.ordinal > after)
            .order_by(SbomDocumentRecord.ordinal)
            .limit(8)
        ).all()
        if not rows:
            return
        for after, content in rows:
            yield json.loads(zlib.decompress(content))


def verify_large_record_counts(db: Session, run_id: str, bom: dict) -> None:
    counts = {
        section: (count, first, last) for section, count, first, last in db.execute(
            select(SbomDocumentRecord.section, func.count(), func.min(SbomDocumentRecord.ordinal),
                   func.max(SbomDocumentRecord.ordinal))
            .where(SbomDocumentRecord.run_id == run_id)
            .group_by(SbomDocumentRecord.section)
        )
    }
    for section in ("components", "dependencies"):
        expected = len(bom.get(section, []))
        actual = counts.get(section, (0, None, None))
        if actual != ((expected, 0, expected - 1) if expected else (0, None, None)):
            raise SbomValidationError("대용량 SBOM의 저장 레코드 수가 업로드 시점과 일치하지 않습니다")
