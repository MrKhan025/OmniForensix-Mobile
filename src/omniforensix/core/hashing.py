"""Streaming cryptographic hashing and evidence integrity verification."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming buffer


@dataclass(frozen=True)
class FileHashDigest:
    """Immutable cryptographic digest record for an evidence file."""

    relative_path: str
    size_bytes: int
    sha256: str
    sha512: str

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def compute_file_hashes(file_path: Path, base_dir: Path | None = None) -> FileHashDigest:
    """Stream a file in fixed chunks and compute both SHA-256 and SHA-512 simultaneously."""
    sha256_hasher = hashlib.sha256()
    sha512_hasher = hashlib.sha512()
    total_bytes = 0

    with file_path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            sha256_hasher.update(chunk)
            sha512_hasher.update(chunk)
            total_bytes += len(chunk)

    rel_path = str(file_path.relative_to(base_dir)) if base_dir else file_path.name
    return FileHashDigest(
        relative_path=rel_path,
        size_bytes=total_bytes,
        sha256=sha256_hasher.hexdigest(),
        sha512=sha512_hasher.hexdigest(),
    )


def build_directory_manifest(root_dir: Path) -> list[FileHashDigest]:
    """Compute deterministic SHA-256/SHA-512 digests for all regular files under root_dir."""
    digests: list[FileHashDigest] = []
    for path in sorted(root_dir.rglob("*")):
        if path.is_file() and not path.is_symlink():
            digests.append(compute_file_hashes(path, base_dir=root_dir))
    return digests


def verify_directory_manifest(root_dir: Path, expected: list[FileHashDigest]) -> tuple[bool, list[str]]:
    """Verify that no file in root_dir was mutated compared to expected digests."""
    mismatches: list[str] = []
    expected_map = {item.relative_path: item for item in expected}
    actual_list = build_directory_manifest(root_dir)
    actual_map = {item.relative_path: item for item in actual_list}

    for rel_path, exp_digest in expected_map.items():
        act_digest = actual_map.get(rel_path)
        if act_digest is None:
            mismatches.append(f"Missing evidence file: {rel_path}")
        elif act_digest.sha256 != exp_digest.sha256 or act_digest.sha512 != exp_digest.sha512:
            mismatches.append(
                f"Hash mismatch for {rel_path}: expected SHA-256 {exp_digest.sha256}, "
                f"got {act_digest.sha256}"
            )

    for rel_path in actual_map:
        if rel_path not in expected_map:
            mismatches.append(f"Unexpected file introduced in evidence tree: {rel_path}")

    return (len(mismatches) == 0, mismatches)
