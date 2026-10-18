"""Bounded Java Pattern compatibility for imported 4.x policy data.

Only patterns and text cross this boundary. Java source, class names, command
options and environment are fixed by the application, never by a policy.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess
import sys

MAX_REQUESTS = 100_000
MAX_PATTERNS = 200
MAX_PATTERN_CHARS = 2048
MAX_VALUE_BYTES = 64 * 1024
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 6
JAVA_BINARY = "/opt/koda-java/bin/java"
CLASS_PATH = Path(__file__).with_name("java")


class JavaRegexError(ValueError):
    """Unavailable runtime, resource exhaustion or malformed runner response."""


class JavaRegexSyntaxError(JavaRegexError):
    """The original Java Pattern syntax is invalid."""


def _encoded(value: str) -> bytes:
    try:
        return base64.b64encode(value.encode("utf-8"))
    except UnicodeError as exc:
        raise JavaRegexError("Java 정규식 입력은 유효한 UTF-8 문자열이어야 합니다") from exc


def evaluate_matches(requests: list[dict], *, validate_only: bool = False) -> list[bool]:
    if not isinstance(requests, list) or len(requests) > MAX_REQUESTS:
        raise JavaRegexError("Java 정규식 평가 횟수가 100,000회 한도를 초과했습니다")
    if not requests:
        return []
    encoded = bytearray(b"KODA_REGEX_V1\t" + (b"V\n" if validate_only else b"E\n"))
    patterns = set()
    for request in requests:
        if not isinstance(request, dict) or set(request) - {"pattern", "value", "mode"}:
            raise JavaRegexError("Java 정규식 요청 구조가 올바르지 않습니다")
        pattern, value, mode = request.get("pattern"), request.get("value"), request.get("mode", "legacy")
        if not isinstance(pattern, str) or len(pattern) > MAX_PATTERN_CHARS or not isinstance(mode, str) or mode not in {"legacy", "raw"}:
            raise JavaRegexError("Java 정규식은 2048자 이하 문자열과 지원되는 모드여야 합니다")
        if value is not None and not isinstance(value, str):
            raise JavaRegexError("Java 정규식 대상은 문자열 또는 null이어야 합니다")
        if value is not None:
            try:
                if len(value) > MAX_VALUE_BYTES or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
                    raise JavaRegexError("Java 정규식 대상이 64 KiB 한도를 초과했습니다")
            except UnicodeError as exc:
                raise JavaRegexError("Java 정규식 입력은 유효한 UTF-8 문자열이어야 합니다") from exc
        patterns.add((mode, pattern))
        if len(patterns) > MAX_PATTERNS:
            raise JavaRegexError("Java 정규식 종류가 200개 한도를 초과했습니다")
        text = b"N" if value is None else b"S" + _encoded(value)
        line = (b"L" if mode == "legacy" else b"R") + b"\t" + _encoded(pattern) + b"\t" + text + b"\n"
        if len(encoded) + len(line) > MAX_INPUT_BYTES:
            raise JavaRegexError("Java 정규식 입력이 4 MiB 한도를 초과했습니다")
        encoded.extend(line)
    binary = os.environ.get("KODA_JAVA_BINARY", JAVA_BINARY)
    class_path = Path(os.environ.get("KODA_JAVA_CLASSPATH", str(CLASS_PATH)))
    if not os.path.isabs(binary) or not class_path.is_absolute() or not Path(binary).is_file() or not (class_path / "RegexMatcher.class").is_file():
        raise JavaRegexError("Java 정규식 런타임 또는 컴파일된 matcher가 설치되지 않았습니다")
    try:
        process = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--child", binary, str(class_path.resolve())],
            input=bytes(encoded), capture_output=True, timeout=TIMEOUT_SECONDS, check=False,
            cwd="/", env={"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}, close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise JavaRegexError("Java 정규식 평가 제한시간(6초)을 초과했습니다") from exc
    except OSError as exc:
        raise JavaRegexError("Java 정규식 격리 프로세스를 실행할 수 없습니다") from exc
    if process.returncode:
        raise JavaRegexError("Java 정규식 격리 프로세스가 실패했습니다(리소스 제한 또는 런타임 오류)")
    if len(process.stdout) > MAX_OUTPUT_BYTES:
        raise JavaRegexError("Java 정규식 결과가 1 MiB 한도를 초과했습니다")
    try:
        lines = process.stdout.decode("ascii").splitlines()
        header = lines[0].split("\t")
        if header[0] == "SYNTAX" and len(header) == 3:
            description = base64.b64decode(header[2], validate=True).decode("utf-8")
            raise JavaRegexSyntaxError("Java 정규식 문법 오류: " + description[:500])
        if header[0] == "ERROR" and len(header) == 2:
            description = base64.b64decode(header[1], validate=True).decode("utf-8")
            raise JavaRegexError("Java 정규식 평가 실패: " + description[:500])
        if header != ["OK", str(len(requests))] or len(lines) != len(requests) + 1 or any(line not in {"0", "1"} for line in lines[1:]):
            raise ValueError("unexpected response")
        return [line == "1" for line in lines[1:]]
    except JavaRegexError:
        raise
    except (ValueError, IndexError, UnicodeError) as exc:
        raise JavaRegexError("Java 정규식 런타임 결과를 읽을 수 없습니다") from exc


def validate_patterns(patterns: list[str], mode: str = "legacy") -> None:
    evaluate_matches([{"pattern": pattern, "value": None, "mode": mode} for pattern in patterns], validate_only=True)


def _launch_java(binary: str, class_path: str) -> None:
    # This fresh isolated Python process applies limits before exec; no unsafe
    # preexec_fn is used in the multithreaded API process.
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    args = [binary, "-Xms16m", "-Xmx64m", "-Xss256k", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1",
            "-XX:MaxMetaspaceSize=64m", "-XX:CompressedClassSpaceSize=32m", "-XX:ReservedCodeCacheSize=16m",
            "-XX:-UsePerfData", "-XX:+ExitOnOutOfMemoryError", "-Dfile.encoding=UTF-8", "-Duser.language=en",
            "-Duser.country=US", "-cp", class_path, "RegexMatcher"]
    os.execve(binary, args, {"PATH": os.defpath, "LANG": "C.UTF-8"})


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--child":
        raise SystemExit(2)
    _launch_java(sys.argv[2], sys.argv[3])
