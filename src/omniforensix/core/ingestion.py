"""Safe evidence archive extraction (ZIP, TAR, Android .ab) and iOS Manifest.db path resolution."""

from __future__ import annotations

import shutil
import tarfile
import zlib
import zipfile
from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists


class SecurityTraversalError(Exception):
    """Raised when an archive member attempts path traversal (Zip-Slip / Tar-Slip)."""


def _validate_target_path(destination_dir: Path, target_path: Path) -> Path:
    resolved_dest = destination_dir.resolve()
    resolved_target = target_path.resolve()
    if not str(resolved_target).startswith(str(resolved_dest)):
        raise SecurityTraversalError(
            f"Blocked path traversal attempt outside workspace: {target_path}"
        )
    return resolved_target


def extract_zip_safely(archive_path: Path, destination_dir: Path) -> list[Path]:
    """Extract a ZIP archive into destination_dir while enforcing Zip-Slip checks."""
    extracted: list[Path] = []
    destination_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            target = _validate_target_path(destination_dir, destination_dir / member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)
    return extracted


def extract_tar_safely(archive_path: Path, destination_dir: Path) -> list[Path]:
    """Extract a TAR/TAR.GZ archive into destination_dir while blocking symlinks and path traversal."""
    extracted: list[Path] = []
    destination_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            target = _validate_target_path(destination_dir, destination_dir / member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is not None:
                with src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                extracted.append(target)
    return extracted


def unpack_android_ab_backup(ab_path: Path, destination_dir: Path) -> list[Path]:
    """Unpack an unencrypted Android ADB backup (.ab) by stripping the 4-line header and inflating the tar stream."""
    raw_bytes = ab_path.read_bytes()
    lines = raw_bytes.split(b"\n", 4)
    if len(lines) < 5 or lines[0] != b"ANDROID BACKUP":
        raise ValueError(f"Invalid Android .ab backup header in {ab_path}")

    compressed_flag = lines[2].strip()
    encryption_alg = lines[3].strip()
    if encryption_alg != b"none":
        raise ValueError(f"Encrypted Android backup ({encryption_alg.decode()}) requires user passphrase.")

    payload = lines[4]
    tar_bytes = zlib.decompress(payload) if compressed_flag == b"1" else payload

    temp_tar = destination_dir / "_unpacked_backup.tar"
    destination_dir.mkdir(parents=True, exist_ok=True)
    temp_tar.write_bytes(tar_bytes)
    try:
        return extract_tar_safely(temp_tar, destination_dir)
    finally:
        if temp_tar.exists():
            temp_tar.unlink()


def resolve_ios_manifest_backup(backup_dir: Path, destination_dir: Path) -> dict[str, Path]:
    """Reconstruct logical iOS file paths from a hashed iTunes/Finder backup directory using Manifest.db."""
    manifest_db = backup_dir / "Manifest.db"
    if not manifest_db.exists() or not table_exists(manifest_db, "Files"):
        return {}

    rows = execute_readonly_query(
        manifest_db,
        "SELECT fileID, domain, relativePath, flags FROM Files WHERE flags = 1 AND relativePath != '';",
    )
    resolved_files: dict[str, Path] = {}
    for row in rows:
        file_id = str(row["fileID"])
        domain = str(row["domain"])
        rel_path = str(row["relativePath"])

        # iOS backups store files either at <backup>/<2-char-prefix>/<fileID> or <backup>/<fileID>
        candidate_nested = backup_dir / file_id[:2] / file_id
        candidate_flat = backup_dir / file_id
        source_file = candidate_nested if candidate_nested.exists() else (candidate_flat if candidate_flat.exists() else None)
        if source_file is None:
            continue

        logical_rel = Path("ios_logical") / domain / rel_path
        target = _validate_target_path(destination_dir, destination_dir / logical_rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)
        resolved_files[f"{domain}/{rel_path}"] = target

    return resolved_files


def ingest_evidence_source(source_path: Path, destination_dir: Path) -> list[Path]:
    """Ingest a directory, iOS backup, or archive (.zip, .tar, .ab) into the case workspace."""
    if source_path.is_file():
        suffix = source_path.suffix.lower()
        if suffix == ".zip":
            return extract_zip_safely(source_path, destination_dir)
        if suffix in {".tar", ".gz", ".tgz"}:
            return extract_tar_safely(source_path, destination_dir)
        if suffix == ".ab":
            return unpack_android_ab_backup(source_path, destination_dir)
        target = destination_dir / source_path.name
        destination_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, target)
        return [target]

    # Source is a directory: copy files preserving structure and also resolve iOS Manifest.db if present
    copied: list[Path] = []
    for item in sorted(source_path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            rel = item.relative_to(source_path)
            target = _validate_target_path(destination_dir, destination_dir / rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            copied.append(target)

    if (source_path / "Manifest.db").exists():
        resolved_map = resolve_ios_manifest_backup(source_path, destination_dir)
        copied.extend(resolved_map.values())

    return copied
