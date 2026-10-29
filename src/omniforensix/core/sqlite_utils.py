"""Forensically sound read-only SQLite access, WAL inspection, and deleted page freelist scanning."""

from __future__ import annotations

import sqlite3
import struct
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import quote


@contextmanager
def open_readonly_sqlite(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Open an SQLite database strictly in read-only URI mode so evidence is never modified."""
    resolved = db_path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"SQLite file does not exist: {resolved}")

    # Do not pass immutable=1 when a -wal file exists alongside the database so read-only queries work safely
    uri_path = quote(str(resolved))
    uri = f"file:{uri_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def execute_readonly_query(db_path: Path, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    """Run a parameterized SELECT query against a read-only SQLite database and return dict rows."""
    with open_readonly_sqlite(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]


def table_exists(db_path: Path, table_name: str) -> bool:
    """Check whether a given table exists inside an SQLite database."""
    rows = execute_readonly_query(
        db_path,
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;",
        (table_name,),
    )
    return len(rows) > 0


def inspect_sqlite_forensic_metadata(db_path: Path) -> dict[str, Any]:
    """Inspect 100-byte SQLite header and companion WAL/journal files for deleted/uncommitted data indicators."""
    header_bytes = db_path.read_bytes()[:100]
    if len(header_bytes) < 100 or not header_bytes.startswith(b"SQLite format 3\x00"):
        raise ValueError(f"Not a valid SQLite 3 database: {db_path}")

    page_size = struct.unpack(">H", header_bytes[16:18])[0]
    if page_size == 1:
        page_size = 65536
    total_pages = struct.unpack(">I", header_bytes[28:32])[0]
    first_freelist_trunk_page = struct.unpack(">I", header_bytes[32:36])[0]
    freelist_page_count = struct.unpack(">I", header_bytes[36:40])[0]

    wal_path = db_path.with_name(db_path.name + "-wal")
    shm_path = db_path.with_name(db_path.name + "-shm")
    journal_path = db_path.with_name(db_path.name + "-journal")

    return {
        "database_path": str(db_path),
        "page_size": page_size,
        "total_pages": total_pages,
        "first_freelist_trunk_page": first_freelist_trunk_page,
        "freelist_page_count": freelist_page_count,
        "has_deleted_freelist_pages": freelist_page_count > 0,
        "has_wal_file": wal_path.exists() and wal_path.stat().st_size > 0,
        "wal_size_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
        "has_rollback_journal": journal_path.exists() and journal_path.stat().st_size > 0,
        "has_shm_file": shm_path.exists(),
    }
