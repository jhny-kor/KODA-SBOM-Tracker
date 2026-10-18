"""Bounded, secret-free subprocess boundary for the official C++ CEL runtime."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

CEL_RUNTIME = "cel-expr-python"
CEL_VERSION = "0.1.3"
MAX_EXPRESSION_BYTES = 8192
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_EVALUATIONS = 100_000
CEL_TIMEOUT_SECONDS = 10
CONTEXT_VARIABLES = ["project", "environment", "release", "run", "component", "vulnerability", "sbomQuality", "now"]


class CelPolicyError(ValueError):
    """A CEL policy could not safely produce a boolean decision."""


def execute_cel(payload: dict) -> dict:
    # JSON roundtrip deliberately rejects custom Python activation objects and NaN.
    try:
        encoded = bytearray()
        for chunk in json.JSONEncoder(ensure_ascii=False, allow_nan=False).iterencode(payload):
            value = chunk.encode()
            if len(encoded) + len(value) > MAX_INPUT_BYTES:
                raise CelPolicyError("CEL 입력이 32 MiB 한도를 초과했습니다")
            encoded.extend(value)
        encoded = bytes(encoded)
    except CelPolicyError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise CelPolicyError("CEL 컨텍스트는 유한한 JSON 기본 값이어야 합니다") from exc
    try:
        process = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("cel_runtime.py"))],
            input=encoded, capture_output=True, timeout=CEL_TIMEOUT_SECONDS, check=False,
            cwd="/", env={"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"},
            close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise CelPolicyError("CEL 평가 제한시간(10초)을 초과했습니다") from exc
    if process.returncode:
        raise CelPolicyError("CEL 격리 프로세스가 실패했습니다(리소스 제한 또는 런타임 오류)")
    if len(process.stdout) > MAX_OUTPUT_BYTES:
        raise CelPolicyError("CEL 결과가 4 MiB 한도를 초과했습니다")
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CelPolicyError("CEL 런타임 결과를 읽을 수 없습니다") from exc
    if not isinstance(result, dict) or not result.get("ok"):
        raise CelPolicyError(str(result.get("error", "CEL 평가 실패"))[:2000] if isinstance(result, dict) else "CEL 평가 실패")
    return result


def validate_expression(expression: str, target: str = "vulnerability", context: dict | None = None) -> dict:
    if target not in {"component", "vulnerability", "project"}:
        raise CelPolicyError("알 수 없는 CEL 평가 대상입니다")
    if not isinstance(expression, str) or not expression.strip() or len(expression.encode()) > MAX_EXPRESSION_BYTES:
        raise CelPolicyError("CEL 표현식은 1~8192바이트여야 합니다")
    payload = {"expressions": [{"id": "preview", "expression": expression, "target": target}], "compileOnly": context is None}
    if context is not None:
        payload["contexts"] = {target: [context]}
    result = execute_cel(payload)
    response = {"valid": True, "runtime": CEL_RUNTIME, "version": CEL_VERSION, "target": target, "contextVariables": CONTEXT_VARIABLES}
    if context is not None:
        response["result"] = bool(result["matches"]["preview"])
    return response
