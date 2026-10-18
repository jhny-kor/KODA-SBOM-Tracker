"""Numeric-distance and Apache Maven 3.9.11 compatibility regression vectors."""
import pytest

from koda_tracker.version_ordering import MavenVersion, maven_distance, maven_is_stable, numeric_version_distance


@pytest.mark.parametrize("ordered", [
    ["1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1", "1-2", "1-123"],
    ["2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"],
    ["6.1.0rc3", "6.1.0", "6.1H.5-beta"],
    ["1-0.alpha", "1-0.beta", "1"],
    ["1.0.0.RC1", "1.0.0-RC2", "1.0.0"],
])
def test_maven_official_ordering_vectors(ordered):
    # Public upstream regression vectors from Apache Maven ComparableVersionTest
    # (Apache-2.0). Exercise every pair to detect transitive-order regressions.
    for index, lower in enumerate(ordered):
        for higher in ordered[index + 1:]:
            assert MavenVersion(lower) < MavenVersion(higher), (lower, higher)
            assert MavenVersion(higher) > MavenVersion(lower), (lower, higher)


@pytest.mark.parametrize("aliases", [
    ["1", "1.0", "1.0.0", "1-0", "1.0-0", "1ga", "1release", "1FINAL"],
    ["1a", "1-a", "1.0-a", "1.0.0-a", "1.0a", "1.0.0a"],
    ["1a1", "1-alpha-1"], ["1b2", "1-beta-2"], ["1m3", "1-MILESTONE3"],
    ["2-RC", "2.0.RC", "2.0.0.RC"], ["00000000000000001", "1"],
])
def test_maven_official_alias_and_normalization_vectors(aliases):
    for left in aliases:
        for right in aliases:
            assert MavenVersion(left) == MavenVersion(right), (left, right)


def test_maven_distance_counts_semantically_distinct_stable_versions():
    versions = ["1.0", "1.0.0", "1.1", "1.1-final", "1.1-sp1", "1.2-beta1", "1.2", "2.0-rc1", "2.0"]
    assert maven_distance(versions, "1.0", "2.0") == 4  # 1.1, 1.1-sp1, 1.2, 2.0
    assert maven_distance(versions, "2.0", "1.0") == 0
    assert not maven_is_stable("2.0-rc1")
    assert not maven_is_stable("2.0a1")
    assert maven_is_stable("2.0-jre")


@pytest.mark.parametrize("current,latest,expected", [
    ("1.2.3", "1.6.0", {"epoch": 0, "major": 0, "minor": 4, "patch": -1}),
    ("v1.2.3", "v3.0.0", {"epoch": 0, "major": 2, "minor": -1, "patch": -1}),
    ("2:1.2.3", "1:9.0.0", {"epoch": 1, "major": -1, "minor": -1, "patch": -1}),
    ("1.2.3", "1.2.9", {"epoch": 0, "major": 0, "minor": 0, "patch": 6}),
    ("1.2.3-beta", "1.2.3", {"epoch": 0, "major": 0, "minor": 0, "patch": 0}),
    ("1", "1.0.0", {"epoch": 0, "major": 0, "minor": 0, "patch": 0}),
    ("vendor", "release", None),
])
def test_numeric_distance_is_first_absolute_difference_not_release_count(current, latest, expected):
    assert numeric_version_distance(current, latest) == expected
