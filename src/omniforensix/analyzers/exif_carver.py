"""Media EXIF/GPS extractor, magic-byte file signature verifier, and SQLite WAL/freelist inspector."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from PIL import Image, ExifTags
from pydantic import BaseModel

from omniforensix.core.sqlite_utils import inspect_sqlite_forensic_metadata

MAGIC_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",),
    ".zip": (b"PK\x03\x04",),
    ".apk": (b"PK\x03\x04",),
    ".db": (b"SQLite format 3\x00",),
    ".sqlite": (b"SQLite format 3\x00",),
    ".plist": (b"bplist00", b"<?xml"),
}


class MediaForensicFinding(BaseModel):
    """Represents EXIF metadata or magic-byte mismatch findings for a file."""

    file_path: str
    detected_magic_hex: str
    extension_mismatch: bool
    camera_make: str | None = None
    camera_model: str | None = None
    datetime_original: str | None = None
    gps_latitude: float | None = None
    gps_longitude: float | None = None


def _dms_to_decimal(dms: tuple[Any, ...], ref: str) -> float | None:
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in {"S", "W"}:
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def analyze_media_and_signatures(workspace_dir: Path) -> list[MediaForensicFinding]:
    """Scan workspace files for magic-byte mismatches and extract EXIF/GPS data from images."""
    findings: list[MediaForensicFinding] = []
    exif_tag_map = {v: k for k, v in ExifTags.TAGS.items()}

    for file_path in sorted(workspace_dir.rglob("*")):
        if not file_path.is_file():
            continue

        head = file_path.read_bytes()[:16]
        ext = file_path.suffix.lower()
        mismatch = False
        if ext in MAGIC_SIGNATURES:
            expected_prefixes = MAGIC_SIGNATURES[ext]
            if not any(head.startswith(prefix) for prefix in expected_prefixes):
                mismatch = True

        camera_make: str | None = None
        camera_model: str | None = None
        dt_orig: str | None = None
        lat: float | None = None
        lon: float | None = None

        if head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG\r\n\x1a\n"):
            try:
                with Image.open(file_path) as img:
                    exif = img.getexif()
                    if exif:
                        camera_make = exif.get(exif_tag_map.get("Make", -1))
                        camera_model = exif.get(exif_tag_map.get("Model", -1))
                        dt_orig = exif.get(exif_tag_map.get("DateTimeOriginal", -1))
                        gps_ifd = exif.get_ifd(0x8825)
                        if gps_ifd:
                            lat_dms = gps_ifd.get(2)
                            lat_ref = gps_ifd.get(1, "N")
                            lon_dms = gps_ifd.get(4)
                            lon_ref = gps_ifd.get(3, "E")
                            if lat_dms and lon_dms:
                                lat = _dms_to_decimal(tuple(lat_dms), str(lat_ref))
                                lon = _dms_to_decimal(tuple(lon_dms), str(lon_ref))
            except Exception:
                pass

        if mismatch or camera_make or camera_model or lat is not None:
            findings.append(
                MediaForensicFinding(
                    file_path=str(file_path.relative_to(workspace_dir)),
                    detected_magic_hex=head[:8].hex(),
                    extension_mismatch=mismatch,
                    camera_make=str(camera_make) if camera_make else None,
                    camera_model=str(camera_model) if camera_model else None,
                    datetime_original=str(dt_orig) if dt_orig else None,
                    gps_latitude=lat,
                    gps_longitude=lon,
                )
            )
    return findings


def scan_sqlite_deleted_records(workspace_dir: Path) -> list[dict[str, Any]]:
    """Identify SQLite databases in the workspace that contain freelist pages or uncommitted WAL journals."""
    results: list[dict[str, Any]] = []
    for file_path in sorted(workspace_dir.rglob("*")):
        if not file_path.is_file():
            continue
        head = file_path.read_bytes()[:16]
        if head.startswith(b"SQLite format 3\x00"):
            info = inspect_sqlite_forensic_metadata(file_path)
            info["relative_path"] = str(file_path.relative_to(workspace_dir))
            results.append(info)
    return results
