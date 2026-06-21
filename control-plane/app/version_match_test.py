from __future__ import annotations

from app.version_match import service_matches


def test_less_than_basic() -> None:
    assert service_matches("1.39.0", "<1.40.2") is True
    assert service_matches("1.40.2", "<1.40.2") is False
    assert service_matches("1.41.0", "<1.40.2") is False


def test_less_than_audiobookshelf() -> None:
    assert service_matches("2.7.0", "<2.17.0") is True
    assert service_matches("2.17.0", "<2.17.0") is False


def test_range_whitespace() -> None:
    assert service_matches("14.0.0", ">=11.1.4 <15.2.3") is True
    assert service_matches("15.2.3", ">=11.1.4 <15.2.3") is False
    assert service_matches("11.0.0", ">=11.1.4 <15.2.3") is False


def test_range_comma() -> None:
    assert service_matches("2.5", ">=2.0,<3.0") is True
    assert service_matches("3.0", ">=2.0,<3.0") is False


def test_fail_open() -> None:
    assert service_matches(None, "<1.40.2") is True
    assert service_matches("garbage", "<1.40.2") is True
    assert service_matches("1.0.0", "") is True
    assert service_matches("1.0.0", "*") is True


def test_equality_default() -> None:
    assert service_matches("1.2.3", "1.2.3") is True
    assert service_matches("1.2.4", "1.2.3") is False


def test_trailing_zero_equivalence() -> None:
    assert service_matches("2.7", "<2.17.0") is True


def test_prerelease_ordering() -> None:
    # PEP 440: a pre-release sorts below its release.
    assert service_matches("1.40.0rc1", "<1.40.2") is True
    assert service_matches("1.0.0rc1", "<1.0.1") is True
    assert service_matches("1.0.0", "<1.0.0") is False
    # PEP 440 boundary rule: "<V" excludes pre-releases of V itself.
    assert service_matches("1.0.0rc1", "<1.0.0") is False
    # Pre-release asset versions are still considered in range (fail toward scan).
    assert service_matches("15.0.0b2", ">=11.1.4 <15.2.3") is True


def test_epoch() -> None:
    # An epoch outranks any non-epoch version regardless of the numerals.
    assert service_matches("2!0.1", ">1.0.0") is True
    assert service_matches("1.0.0", ">1.0.0") is False


def test_non_semver_vendor_fallback() -> None:
    # Not valid PEP 440 -> hand-rolled dotted comparator handles it.
    assert service_matches("2.7.11p2", "<2.8") is True
    assert service_matches("2.7.11p2", ">=2.8") is False
