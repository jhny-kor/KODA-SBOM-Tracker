import pytest

from koda_tracker.upgrade_native_versions import deb_version_key, rpm_version_key


@pytest.mark.parametrize(("left", "right"), [
    ("1.0~rc1-1", "1.0-1"),
    ("1.0-1", "1.0^20241101-1"),
    ("1.0^20241101-1", "1.0.1-1"),
    ("1.0-1.el8", "1.0-1.el9"),
    ("1.0-9.el8", "1.0-10.el8"),
    ("1.0b-1", "1.0.1-1"),
    ("9.1-100", "1:1.0-1"),
])
def test_rpm_order(left, right):
    assert rpm_version_key(left) < rpm_version_key(right)


def test_rpm_evr_requires_a_release():
    assert rpm_version_key("01:1+.+2-01_09") == rpm_version_key("1:1.2-1.9")
    for invalid in ("1.2", "1.2-", "1.2-1-2", "-1:1.2-1", "x:1.2-1", "1.2-~", "1.0/2-1"):
        assert rpm_version_key(invalid) is None


@pytest.mark.parametrize(("left", "right"), [
    ("1.0~~rc1-1", "1.0~rc1-1"),
    ("1.0~rc1-1", "1.0-1"),
    ("1.0-1~bpo12+2", "1.0-1"),
    ("1.0-1", "1.0-1+b2"),
    ("1.0-1+b2", "1.0-1+b10"),
    ("1.0-1a", "1.0-1+"),
    ("1.0-1", "1.0-10"),
    ("9.1-100", "1:1.0-1"),
    ("1:1.0:2-1", "1:1.0:10-1"),
    ("2:1.0-1", "10:0.1-0"),
])
def test_debian_order(left, right):
    assert deb_version_key(left) < deb_version_key(right)


def test_debian_zero_and_invalid_versions():
    assert deb_version_key("1.000") == deb_version_key("0:1.0-0")
    assert deb_version_key("1.0-1ubuntu") == deb_version_key("1.0-1ubuntu0")
    for invalid in ("", "abc", "1.0-", "1.0-1^", "x:1.0-1", "1.0-1_0", "2147483648:1.0"):
        assert deb_version_key(invalid) is None
