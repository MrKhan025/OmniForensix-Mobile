"""Unit tests for Android WhatsApp .db.crypt14 and .db.crypt15 AES-256-GCM decryption."""

import sqlite3
from pathlib import Path

from omniforensix.core.crypto_decryptor import (
    auto_decrypt_workspace_databases,
    decrypt_whatsapp_crypt_file,
    encrypt_sqlite_to_crypt,
)
from omniforensix.plugins.android.whatsapp import AndroidWhatsAppPlugin


def _build_sample_msgstore_bytes(tmp_path: Path) -> bytes:
    db_file = tmp_path / "raw_msgstore.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);")
    conn.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER);")
    conn.execute(
        """CREATE TABLE message (
            _id INTEGER PRIMARY KEY,
            chat_row_id INTEGER,
            from_me INTEGER,
            timestamp INTEGER,
            text_data TEXT,
            message_type INTEGER
        );"""
    )
    conn.execute("INSERT INTO jid VALUES (1, '15559999@s.whatsapp.net');")
    conn.execute("INSERT INTO chat VALUES (1, 1);")
    conn.execute(
        "INSERT INTO message VALUES (1, 1, 0, 1700004000000, 'Decrypted crypt14 secret payload', 0);"
    )
    conn.commit()
    conn.close()
    return db_file.read_bytes()


def test_decrypt_whatsapp_crypt14_with_158_byte_key_file(tmp_path: Path) -> None:
    sqlite_bytes = _build_sample_msgstore_bytes(tmp_path)
    aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

    # Build a synthetic 158-byte Android WhatsApp key file (bytes 126..158 hold the 32-byte key)
    key_file = tmp_path / "key"
    key_file.write_bytes((b"\x00" * 126) + aes_key)

    crypt14_file = tmp_path / "msgstore.db.crypt14"
    crypt14_file.write_bytes(encrypt_sqlite_to_crypt(sqlite_bytes, aes_key, version=14))

    res = decrypt_whatsapp_crypt_file(crypt14_file, key_file)
    decrypted_path = Path(res.decrypted_target)
    assert decrypted_path.exists()
    assert decrypted_path.name == "msgstore.db"

    records = AndroidWhatsAppPlugin().run(tmp_path)
    assert len(records) == 1
    assert "Decrypted crypt14 secret payload" in records[0].attributes["body"]


def test_decrypt_whatsapp_crypt15_with_64_digit_hex_key(tmp_path: Path) -> None:
    sqlite_bytes = _build_sample_msgstore_bytes(tmp_path)
    hex_key = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    root_key = bytes.fromhex(hex_key)

    ws_dir = tmp_path / "ws_crypt15"
    ws_dir.mkdir(parents=True)
    crypt15_file = ws_dir / "msgstore.db.crypt15"
    crypt15_file.write_bytes(encrypt_sqlite_to_crypt(sqlite_bytes, root_key, version=15))

    results = auto_decrypt_workspace_databases(ws_dir, explicit_key=hex_key)
    assert len(results) == 1
    assert (ws_dir / "msgstore.db").exists()
