"""Unit tests for forensic timestamp normalization across Unix, Cocoa, and WebKit epochs."""

from omniforensix.core.timestamps import EpochType, normalize_timestamp


def test_unix_milliseconds_to_utc() -> None:
    ts = normalize_timestamp(1700000000000, EpochType.UNIX_MILLIS)
    assert ts is not None
    assert ts.utc_iso8601 == "2023-11-14T22:13:20.000000Z"


def test_mac_absolute_seconds_to_utc() -> None:
    # 721692800 + 978307200 = 1700000000
    ts = normalize_timestamp(721692800, EpochType.MAC_ABSOLUTE_SECONDS)
    assert ts is not None
    assert ts.utc_iso8601 == "2023-11-14T22:13:20.000000Z"


def test_mac_absolute_nanoseconds_to_utc() -> None:
    ts = normalize_timestamp(721692800_000_000_000, EpochType.MAC_ABSOLUTE_NANOS)
    assert ts is not None
    assert ts.utc_iso8601 == "2023-11-14T22:13:20.000000Z"


def test_webkit_microseconds_to_utc() -> None:
    # (1700000000 * 1_000_000) + 11644473600000000 = 13344473600000000
    ts = normalize_timestamp(13344473600000000, EpochType.WEBKIT_MICROS)
    assert ts is not None
    assert ts.utc_iso8601 == "2023-11-14T22:13:20.000000Z"
