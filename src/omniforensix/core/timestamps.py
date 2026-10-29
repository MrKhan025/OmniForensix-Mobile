"""Forensic timestamp normalization across Unix, Cocoa/Mac Absolute Time, and WebKit epochs."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field

MAC_ABSOLUTE_EPOCH_OFFSET = 978307200  # Seconds between 1970-01-01 and 2001-01-01
WEBKIT_EPOCH_OFFSET_MICROSECONDS = 11644473600000000  # Microseconds between 1601-01-01 and 1970-01-01


class EpochType(str, Enum):
    UNIX_SECONDS = "unix_seconds"
    UNIX_MILLIS = "unix_milliseconds"
    UNIX_MICROS = "unix_microseconds"
    UNIX_NANOS = "unix_nanoseconds"
    MAC_ABSOLUTE_SECONDS = "mac_absolute_seconds"
    MAC_ABSOLUTE_NANOS = "mac_absolute_nanoseconds"
    WEBKIT_MICROS = "webkit_microseconds"
    ISO8601_STRING = "iso8601_string"


class ForensicTimestamp(BaseModel):
    """Structured forensic timestamp preserving raw source value and normalized UTC ISO-8601."""

    raw_value: int | float | str = Field(..., description="Original raw timestamp value in artifact")
    epoch_type: EpochType = Field(..., description="Detected or specified timestamp epoch scheme")
    timezone_offset: str = Field(default="UTC", description="Original timezone offset if recorded")
    utc_iso8601: str = Field(..., description="Normalized UTC timestamp in YYYY-MM-DDTHH:MM:SS.ffffffZ")
    unix_epoch_seconds: float = Field(..., description="Normalized POSIX timestamp in seconds")


def _format_utc(unix_seconds: float) -> str:
    dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalize_timestamp(
    raw_value: int | float | str | None,
    epoch_type: EpochType | None = None,
    timezone_offset: str = "UTC",
) -> ForensicTimestamp | None:
    """Convert raw forensic timestamps into normalized UTC ISO-8601 records."""
    if raw_value is None or raw_value == "" or raw_value == 0 or raw_value == "0":
        return None

    if isinstance(raw_value, str) and epoch_type == EpochType.ISO8601_STRING:
        cleaned = raw_value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned).astimezone(timezone.utc)
        unix_sec = dt.timestamp()
        return ForensicTimestamp(
            raw_value=raw_value,
            epoch_type=EpochType.ISO8601_STRING,
            timezone_offset=timezone_offset,
            utc_iso8601=_format_utc(unix_sec),
            unix_epoch_seconds=unix_sec,
        )

    num_val = float(raw_value)

    if epoch_type is None:
        # Heuristic auto-detection for numeric Unix timestamps when not explicitly provided
        if num_val > 1e17:
            epoch_type = EpochType.UNIX_NANOS
        elif num_val > 1e14:
            epoch_type = EpochType.UNIX_MICROS
        elif num_val > 1e11:
            epoch_type = EpochType.UNIX_MILLIS
        else:
            epoch_type = EpochType.UNIX_SECONDS

    if epoch_type == EpochType.UNIX_SECONDS:
        unix_sec = num_val
    elif epoch_type == EpochType.UNIX_MILLIS:
        unix_sec = num_val / 1_000.0
    elif epoch_type == EpochType.UNIX_MICROS:
        unix_sec = num_val / 1_000_000.0
    elif epoch_type == EpochType.UNIX_NANOS:
        unix_sec = num_val / 1_000_000_000.0
    elif epoch_type == EpochType.MAC_ABSOLUTE_SECONDS:
        unix_sec = num_val + MAC_ABSOLUTE_EPOCH_OFFSET
    elif epoch_type == EpochType.MAC_ABSOLUTE_NANOS:
        unix_sec = (num_val / 1_000_000_000.0) + MAC_ABSOLUTE_EPOCH_OFFSET
    elif epoch_type == EpochType.WEBKIT_MICROS:
        unix_sec = (num_val - WEBKIT_EPOCH_OFFSET_MICROSECONDS) / 1_000_000.0
    else:
        raise ValueError(f"Unsupported epoch_type: {epoch_type}")

    return ForensicTimestamp(
        raw_value=raw_value,
        epoch_type=epoch_type,
        timezone_offset=timezone_offset,
        utc_iso8601=_format_utc(unix_sec),
        unix_epoch_seconds=unix_sec,
    )
