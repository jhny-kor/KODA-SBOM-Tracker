from __future__ import annotations

import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from koda_tracker import java_regex as regex


@pytest.fixture(autouse=True)
def clear_test_classpath_override(monkeypatch):
    monkeypatch.delenv("KODA_JAVA_CLASSPATH", raising=False)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = os.environ.get("KODA_JAVA_HOME")
    java = str(Path(home) / "bin/java") if home else os.environ.get("KODA_JAVA_BINARY", regex.JAVA_BINARY)
    javac = str(Path(home) / "bin/javac") if home else str(Path(java).with_name("javac"))
    if not Path(java).is_file() or not Path(javac).is_file():
        pytest.skip("Actual JDK required; set KODA_JAVA_HOME")
    subprocess.run([javac, "-encoding", "UTF-8", "-d", str(tmp_path), str(regex.CLASS_PATH / "RegexMatcher.java")], check=True, capture_output=True)
    monkeypatch.setattr(regex, "CLASS_PATH", tmp_path)
    monkeypatch.setenv("KODA_JAVA_BINARY", java)
    return tmp_path


@pytest.mark.parametrize("pattern,value,expected", [
    (r"(?<=pkg:)pypi/sample", "pkg:pypi/sample@1", True),
    (r"(?<!dev-)sample", "pkg:pypi/dev-sample@1", False),
    (r"(sample)-\1", "pkg:pypi/sample-sample@1", True),
    (r"(?<part>sample)-\k<part>", "pkg:pypi/sample-sample@1", True),
    (r"[a-z&&[^aeiou]]{3}", "pkg:pypi/str@1", True),
    (r"^[a-z&&[^aeiou]]{3}$", "aei", False),
    (r"\Qsample[1]\E", "pkg:pypi/sample[1]@1", True),
    (r"(?i)SAMPLE", "pkg:pypi/sample@1", True),
    (r"(?>ab|a)b", "ab", False),
    (r"a++a", "aaaa", False),
    (r"\p{IsHangul}+", "패키지", True),
    (r"^sample$", "prefix-sample", False),
    (r"sample*", "prefix-sample-suffix", True),
    (r"^$", "", True),
    (r".*", None, False),
])
def test_actual_java_specific_patterns(runtime, pattern, value, expected):
    assert regex.evaluate_matches([{"pattern": pattern, "value": value}]) == [expected]


def test_raw_full_match_and_legacy_wildcard_modes_are_distinct(runtime):
    assert regex.evaluate_matches([
        {"pattern": "sample", "value": "pkg:pypi/sample@1", "mode": "raw"},
        {"pattern": "sample", "value": "pkg:pypi/sample@1", "mode": "legacy"},
        {"pattern": "sample", "value": "sample", "mode": "raw"},
    ]) == [False, True, True]


def test_batch_encoding_preserves_tabs_newlines_and_unicode(runtime):
    assert regex.evaluate_matches([
        {"pattern": "(?s)^a.*b$", "value": "a\t\n한글b", "mode": "raw"},
        {"pattern": "^b$", "value": "a", "mode": "raw"},
    ]) == [True, False]


def test_java_syntax_validation_even_without_target(runtime):
    regex.validate_patterns([r"(?<=pkg:)pypi", r"(?<id>sample)-\k<id>"])
    with pytest.raises(regex.JavaRegexSyntaxError, match="문법"):
        regex.validate_patterns(["["])


def test_resource_exhaustion_does_not_return_nonmatch(runtime):
    # Java's recursive matcher exhausts the deliberately bounded thread stack.
    with pytest.raises(regex.JavaRegexError, match="평가 실패|프로세스가 실패|제한시간"):
        regex.evaluate_matches([{"pattern": r"^(a|aa)+$", "value": "a" * 50_000 + "!", "mode": "raw"}])


@pytest.mark.parametrize("requests", [
    [{"pattern": "x" * 2049, "value": "x"}],
    [{"pattern": "x", "value": "한" * 30_000}],
    [{"pattern": "x", "value": 1}],
    [{"pattern": "x", "value": "x", "mode": "exec"}],
    [{"pattern": "x", "value": "x", "mode": []}],
    [{"pattern": "x", "value": "x", "command": "bad"}],
    [{"pattern": str(i), "value": "x"} for i in range(201)],
])
def test_input_limits_precede_runtime(requests):
    with pytest.raises(regex.JavaRegexError):
        regex.evaluate_matches(requests)


def test_missing_runtime_is_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("KODA_JAVA_BINARY", str(tmp_path / "missing-java"))
    with pytest.raises(regex.JavaRegexError, match="설치"):
        regex.evaluate_matches([{"pattern": "x", "value": "x"}])


def test_timeout_and_invalid_output_fail_closed(monkeypatch, tmp_path):
    binary = tmp_path / "java"; binary.touch()
    (tmp_path / "RegexMatcher.class").touch()
    monkeypatch.setenv("KODA_JAVA_BINARY", str(binary))
    monkeypatch.setattr(regex, "CLASS_PATH", tmp_path)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 6)
    monkeypatch.setattr(regex.subprocess, "run", timeout)
    with pytest.raises(regex.JavaRegexError, match="제한시간"):
        regex.evaluate_matches([{"pattern": "x", "value": "x"}])
    monkeypatch.setattr(regex.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"OK\t1\nmaybe\n"))
    with pytest.raises(regex.JavaRegexError, match="읽을 수"):
        regex.evaluate_matches([{"pattern": "x", "value": "x"}])


def test_empty_batch_never_requires_java():
    assert regex.evaluate_matches([]) == []


def test_patterns_stay_stdin_data_and_child_environment_omits_secrets(monkeypatch, tmp_path):
    binary = tmp_path / "java"; binary.touch()
    (tmp_path / "RegexMatcher.class").touch()
    monkeypatch.setenv("KODA_JAVA_BINARY", str(binary))
    monkeypatch.setenv("DATABASE_PASSWORD", "never-forward-this")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Dsecret=never-forward-this")
    monkeypatch.setattr(regex, "CLASS_PATH", tmp_path)
    seen = {}
    def execute(args, **kwargs):
        seen.update(args=args, **kwargs)
        return SimpleNamespace(returncode=0, stdout=b"OK\t1\n1\n")
    monkeypatch.setattr(regex.subprocess, "run", execute)
    assert regex.evaluate_matches([{"pattern": "(?<name>sample)-\\k<name>", "value": "sample-sample"}]) == [True]
    assert "sample" not in " ".join(seen["args"])
    assert set(seen["env"]) == {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE"}
    assert b"never-forward-this" not in seen["input"]
