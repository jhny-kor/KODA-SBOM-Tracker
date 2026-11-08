#!/usr/bin/env python3
"""Project a native Maven dependency:tree JSON report into Tracker evidence."""
import argparse
import hashlib
import json
import re
from pathlib import Path

COORDINATE_PART = re.compile(r"[A-Za-z0-9_.-]+")
MAX_REPORT_BYTES = 4 * 1024 * 1024


def project(report: bytes) -> list[dict]:
    root = json.loads(report)
    if not isinstance(root, dict) or not isinstance(root.get("groupId"), str) or not isinstance(root.get("artifactId"), str):
        raise ValueError("배포 모듈 하나의 Maven dependency:tree JSON을 지정하세요")
    pending = root.get("children", [])
    if not isinstance(pending, list):
        raise ValueError("Maven 의존성 트리의 children을 읽을 수 없습니다")
    selected = set()
    count = 0
    while pending:
        item = pending.pop()
        count += 1
        if not isinstance(item, dict) or count > 10_000:
            raise ValueError("Maven 의존성 트리 형식 또는 크기가 지원 범위를 벗어났습니다")
        group, artifact, version = (item.get(key) for key in ("groupId", "artifactId", "version"))
        if (not isinstance(group, str) or not isinstance(artifact, str) or not isinstance(version, str)
                or not COORDINATE_PART.fullmatch(group) or not COORDINATE_PART.fullmatch(artifact)
                or len(group) + len(artifact) > 500 or not 1 <= len(version) <= 255):
            raise ValueError("Maven 좌표 또는 버전이 올바르지 않습니다")
        if item.get("scope") not in {"compile", "runtime"}:
            raise ValueError("dependency:tree에 -Dscope=runtime을 지정하고 배포 모듈의 결과를 사용하세요")
        selected.add((f"pkg:maven/{group}/{artifact}", version))
        children = item.get("children", [])
        if not isinstance(children, list) or len(selected) > 1500:
            raise ValueError("Maven 의존성 형식 또는 수량이 지원 범위를 벗어났습니다")
        pending.extend(children)
    if not selected:
        raise ValueError("Maven 보고서에 런타임 의존성이 없습니다")
    return [{"coordinate": name, "version": version} for name, version in sorted(selected)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--source", required=True, help="격리 CI 실행 ID 또는 보고서 식별자")
    parser.add_argument("--maven-version", required=True)
    parser.add_argument("--java-major", required=True, type=int)
    parser.add_argument("--minimum-java-major", type=int)
    parser.add_argument("--java-requirement-evidence")
    args = parser.parse_args()
    try:
        with args.report.open("rb") as file:
            raw = file.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("Maven 보고서가 4 MiB를 초과합니다")
        if not 6 <= args.java_major <= 99:
            raise ValueError("Java 버전은 6~99 사이여야 합니다")
        if args.minimum_java_major is not None and not 6 <= args.minimum_java_major <= 99:
            raise ValueError("최소 Java 버전은 6~99 사이여야 합니다")
        if bool(args.minimum_java_major) != bool(args.java_requirement_evidence and args.java_requirement_evidence.strip()):
            raise ValueError("최소 Java 버전과 그 근거를 함께 지정하세요")
        selected = project(raw)
    except (OSError, ValueError, RecursionError) as exc:
        parser.error(str(exc))
    result = {"kind": "maven", "source": args.source, "outcome": "resolved",
              "javaMajor": args.java_major, "mavenVersion": args.maven_version,
              "reportSha256": hashlib.sha256(raw).hexdigest(), "selected": selected}
    if args.minimum_java_major:
        result.update(minimumJavaMajor=args.minimum_java_major, javaRequirementEvidence=args.java_requirement_evidence)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
