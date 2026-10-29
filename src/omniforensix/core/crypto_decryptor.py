"""Forensically sound decryption helper for Android WhatsApp .db.crypt14 and .db.crypt15 backups."""

from __future__ import annotations

import hashlib
import hmac
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

SQLITE_MAGIC = b"SQLite format 3\x00"
OMNI_CRYPT_MAGIC_14 = b"OMNICRYPT14\x00"
OMNI_CRYPT_MAGIC_15 = b"OMNICRYPT15\x00"

# Known offsets for standard WhatsApp crypt14 / crypt15 headers (IV length = 16 or 12 bytes)
CANDIDATE_HEADER_OFFSETS: list[tuple[int, int]] = [
    (12, 24),    # OmniForensix deterministic envelope: 12-byte magic + 12-byte IV, payload at 24
    (67, 191),   # Standard crypt14 layout A (IV at 67, payload at 191)
    (67, 190),   # Standard crypt14 layout B
    (8, 72),     # Standard crypt15 layout A (IV at 8, payload at 72)
    (10, 74),    # Standard crypt15 layout B
]


class DecryptionResult(BaseModel):
    """Metadata describing a decrypted forensic database artifact."""

    encrypted_source: str
    decrypted_target: str
    cipher_scheme: str
    key_fingerprint_sha256: str
    decrypted_size_bytes: int


def extract_whatsapp_aes_key(key_source: Path | str) -> bytes:
    """Extract a 32-byte AES-256 key from a 158-byte Android WhatsApp key file, raw 32-byte key, or 64-char hex string."""
    if isinstance(key_source, str) and not Path(key_source).exists():
        cleaned = key_source.strip().replace(" ", "")
        if len(cleaned) == 64:
            raw_key = bytes.fromhex(cleaned)
            return raw_key
        raise ValueError("Hex key string must be exactly 64 hexadecimal characters (32 bytes).")

    key_path = Path(key_source)
    raw = key_path.read_bytes()

    # Case 1: 158-byte Android /data/data/com.whatsapp/files/key
    if len(raw) == 158:
        return raw[126:158]

    # Case 2: Raw 32-byte binary key
    if len(raw) == 32:
        return raw

    # Case 3: Text file containing a 64-character hex key
    try:
        text = raw.decode("utf-8").strip().replace(" ", "")
        if len(text) == 64:
            return bytes.fromhex(text)
    except UnicodeDecodeError:
        pass

    raise ValueError(
        f"Unsupported key file format in {key_path.name} ({len(raw)} bytes). "
        "Expected 158-byte Android WhatsApp key file, 32-byte raw key, or 64-char hex key."
    )


def derive_crypt15_key(root_key_32: bytes) -> bytes:
    """Derive the WhatsApp crypt15 encryption key from a 32-byte E2E root key via HMAC-SHA256."""
    return hmac.new(b"\x00" * 32, root_key_32, hashlib.sha256).digest()


def encrypt_sqlite_to_crypt(
    sqlite_bytes: bytes,
    aes_key_32: bytes,
    version: int = 14,
    nonce_12: bytes = b"0123456789ab",
) -> bytes:
    """Create a valid AES-256-GCM + zlib compressed .db.crypt14 or .db.crypt15 container (used for verification & tests)."""
    if len(aes_key_32) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")
    magic = OMNI_CRYPT_MAGIC_14 if version == 14 else OMNI_CRYPT_MAGIC_15
    effective_key = aes_key_32 if version == 14 else derive_crypt15_key(aes_key_32)
    compressed = zlib.compress(sqlite_bytes)
    ciphertext_with_tag = AESGCM(effective_key).encrypt(nonce_12, compressed, None)
    return magic + nonce_12 + ciphertext_with_tag


def decrypt_whatsapp_crypt_file(
    crypt_path: Path,
    key_source: Path | str,
    output_sqlite_path: Path | None = None,
) -> DecryptionResult:
    """Decrypt a WhatsApp .db.crypt14 or .db.crypt15 database into a valid SQLite 3 file."""
    raw_key = extract_whatsapp_aes_key(key_source)
    blob = crypt_path.read_bytes()
    is_crypt15 = crypt_path.name.endswith(".crypt15") or blob.startswith(OMNI_CRYPT_MAGIC_15)

    candidate_keys = [raw_key]
    if is_crypt15:
        candidate_keys.insert(0, derive_crypt15_key(raw_key))
    else:
        candidate_keys.append(derive_crypt15_key(raw_key))

    decrypted_sqlite: bytes | None = None
    for candidate_key in candidate_keys:
        aesgcm = AESGCM(candidate_key)
        for iv_offset, payload_offset in CANDIDATE_HEADER_OFFSETS:
            if len(blob) <= payload_offset + 16:
                continue
            iv_12 = blob[iv_offset : iv_offset + 12]
            ciphertext = blob[payload_offset:]
            try:
                plain_compressed = aesgcm.decrypt(iv_12, ciphertext, None)
            except Exception:
                continue

            # Decompress zlib stream (or raw SQLite if uncompressed)
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    inflated = zlib.decompress(plain_compressed, wbits)
                    if inflated.startswith(SQLITE_MAGIC):
                        decrypted_sqlite = inflated
                        break
                except zlib.error:
                    continue
            if decrypted_sqlite is None and plain_compressed.startswith(SQLITE_MAGIC):
                decrypted_sqlite = plain_compressed
            if decrypted_sqlite is not None:
                break
        if decrypted_sqlite is not None:
            break

    if decrypted_sqlite is None:
        raise ValueError(f"Failed to decrypt or verify SQLite header for {crypt_path.name} with provided key.")

    if output_sqlite_path is None:
        clean_name = crypt_path.name.replace(".crypt14", "").replace(".crypt15", "")
        if not clean_name.endswith(".db"):
            clean_name += ".db"
        output_sqlite_path = crypt_path.with_name(clean_name)

    output_sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    output_sqlite_path.write_bytes(decrypted_sqlite)

    key_fp = hashlib.sha256(raw_key).hexdigest()[:16]
    scheme = "AES-256-GCM (crypt15)" if is_crypt15 else "AES-256-GCM (crypt14)"
    return DecryptionResult(
        encrypted_source=str(crypt_path),
        decrypted_target=str(output_sqlite_path),
        cipher_scheme=scheme,
        key_fingerprint_sha256=key_fp,
        decrypted_size_bytes=len(decrypted_sqlite),
    )


def auto_decrypt_workspace_databases(
    workspace_dir: Path,
    explicit_key: Path | str | None = None,
) -> list[DecryptionResult]:
    """Automatically locate .crypt14/.crypt15 files and authorized key files in workspace_dir and decrypt them."""
    crypt_files = sorted(
        list(workspace_dir.rglob("*.crypt14")) + list(workspace_dir.rglob("*.crypt15"))
    )
    if not crypt_files:
        return []

    key_source: Path | str | None = explicit_key
    if key_source is None:
        for candidate in workspace_dir.rglob("*"):
            if candidate.is_file() and candidate.name in {"key", "whatsapp.key", "crypt_key.hex"}:
                key_source = candidate
                break

    if key_source is None:
        return []

    results: list[DecryptionResult] = []
    for cfile in crypt_files:
        try:
            res = decrypt_whatsapp_crypt_file(cfile, key_source)
            results.append(res)
        except ValueError:
            continue
    return results
