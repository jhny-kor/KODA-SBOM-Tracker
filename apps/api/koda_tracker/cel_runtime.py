"""Private CEL child process. Only standard CEL, JSON data, and bounded output.

This module is executed by absolute path under Python isolated mode. It must not
import application settings, database code, or expose host callback functions.
"""
from __future__ import annotations

from datetime import datetime, UTC
import json
import resource
import sys


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    else:
        # macOS ignores RLIMIT_AS for some mappings; cap resident set too. The
        # independent parent timeout remains enforced on every platform.
        try:
            resource.setrlimit(resource.RLIMIT_RSS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        except (ValueError, OSError):
            pass


def main() -> dict:
    _limits()
    from cel_expr_python import cel

    payload = json.loads(sys.stdin.buffer.read(32 * 1024 * 1024 + 1))
    expressions = payload.get("expressions", [])
    if len(expressions) > 200:
        raise ValueError("CEL 정책 수가 200개 한도를 초과했습니다")
    env = cel.NewEnv(variables={**{name: cel.Type.DYN for name in ("project", "environment", "release", "run", "component", "vulnerability")}, "now": cel.Type.TIMESTAMP})
    compiled = []
    for rule in expressions:
        expression = rule["expression"]
        if not isinstance(expression, str) or not expression.strip() or len(expression.encode()) > 8192:
            raise ValueError("CEL 표현식은 1~8192바이트여야 합니다")
        try:
            program = env.compile(expression)
            if program.return_type() not in (cel.Type.BOOL, cel.Type.DYN):
                raise ValueError("CEL 정책은 bool 결과를 반환해야 합니다")
        except Exception as exc:
            raise ValueError(f"CEL 정책 {rule['id']} 컴파일 실패: {exc}") from exc
        compiled.append((rule, program))
    if payload.get("compileOnly"):
        return {"ok": True, "matches": {}}
    contexts = payload.get("contexts", {})
    evaluations = 0
    matches = {}
    for rule, program in compiled:
        indexes = []
        for index, raw in enumerate(contexts.get(rule["target"], [])):
            evaluations += 1
            if evaluations > 100_000:
                raise ValueError("CEL 평가 횟수가 100,000회 한도를 초과했습니다")
            data = dict(raw)
            if "now" in data:
                data["now"] = datetime.fromisoformat(data["now"].replace("Z", "+00:00")).astimezone(UTC)
            try:
                value = program.eval(data=data)
                if value.type() != cel.Type.BOOL:
                    raise ValueError(f"bool 결과가 아닙니다: {value}")
                if value.value():
                    indexes.append(index)
            except Exception as exc:
                raise ValueError(f"CEL 정책 {rule['id']} 평가 실패(대상 {index}): {exc}") from exc
        matches[rule["id"]] = indexes
    return {"ok": True, "matches": matches, "evaluations": evaluations}


if __name__ == "__main__":
    try:
        response = main()
    except BaseException as exc:
        response = {"ok": False, "error": str(exc)[:2000]}
    sys.stdout.write(json.dumps(response, ensure_ascii=False, allow_nan=False))
