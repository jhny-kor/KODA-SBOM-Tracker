#!/usr/bin/env python3
"""Export a self-contained migration bundle via the source's read-only API.

Import/review/apply uses the authenticated KODA migration screen or API. The key
is read from an environment variable; it is never accepted as a CLI argument.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api"))


def main() -> int:
    parser = argparse.ArgumentParser(description="기존 분석 서버에서 검토 가능한 이관 JSON 번들을 내보냅니다")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--allowed-origin", action="append", required=True)
    parser.add_argument("--api-key-env", default="LEGACY_SOURCE_API_KEY")
    parser.add_argument("--project-uuid", action="append", default=[])
    parser.add_argument("--source-time-zone", default=None, help="원본 JVM 시간대를 명시합니다. AGE 자동변환은 UTC만 지원합니다")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    key = os.environ.get(args.api_key_env, "")
    if not key:
        parser.error("지정한 환경변수에 원본 API 키가 없습니다")
    from koda_tracker.migration import LegacyExporter, MigrationError
    exporter = None
    try:
        exporter = LegacyExporter(args.base_url, key, args.allowed_origin, source_timezone=args.source_time_zone)
        bundle = exporter.export(args.project_uuid)
        raw = json.dumps(bundle, ensure_ascii=False, indent=2, allow_nan=False).encode()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(raw)
        print(json.dumps({"output": str(args.output), "projects": len(bundle["projects"]), "policies": len(bundle["policies"]), "sha256": hashlib.sha256(raw).hexdigest()}, ensure_ascii=False))
        return 0
    except (MigrationError, OSError, ValueError, KeyError, TypeError) as exc:
        print("이관 번들 내보내기 실패: " + str(exc)[:2000], file=sys.stderr)
        return 1
    finally:
        if exporter:
            exporter.close()


if __name__ == "__main__":
    raise SystemExit(main())
