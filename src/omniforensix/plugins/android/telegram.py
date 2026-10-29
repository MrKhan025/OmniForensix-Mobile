"""Telegram SQLite database parser (cache4.db on Android / tgdata.db on iOS)."""

from __future__ import annotations

import re
from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin

PRINTABLE_UTF8_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _extract_readable_payload(raw_data: bytes | str | None) -> str:
    """Extract readable text strings from Telegram TL-serialized BLOB payloads or plaintext columns."""
    if raw_data is None:
        return ""
    if isinstance(raw_data, str):
        return raw_data
    if isinstance(raw_data, bytes):
        matches = [m.decode("utf-8", errors="ignore") for m in PRINTABLE_UTF8_RE.findall(raw_data)]
        return " | ".join(matches)
    return str(raw_data)


@register_plugin
class TelegramCachePlugin(ArtifactPlugin):
    name = "telegram_cache_parser"
    os_type = OSType.CROSS_PLATFORM
    category = "Third-Party Messaging"
    description = "Parses Telegram cache4.db and tgdata.db (messages_v2, messages, and users tables)"
    target_globs = ("*cache4.db", "*tgdata.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        user_map: dict[int, str] = {}
        if table_exists(file_path, "users"):
            for urow in execute_readonly_query(file_path, "SELECT uid, name, status FROM users;"):
                uid = int(urow.get("uid") or 0)
                user_map[uid] = str(urow.get("name") or uid)

        msg_table = "messages_v2" if table_exists(file_path, "messages_v2") else (
            "messages" if table_exists(file_path, "messages") else None
        )
        if msg_table is None:
            return records

        rows = execute_readonly_query(
            file_path,
            f"SELECT mid, uid, date, out, read_state, data FROM {msg_table} ORDER BY date ASC;",  # noqa: S608
        )
        for row in rows:
            uid = int(row.get("uid") or 0)
            peer_name = user_map.get(uid, f"uid:{uid}")
            direction = "Outgoing" if row.get("out") else "Incoming"
            body = _extract_readable_payload(row.get("data"))
            ts = normalize_timestamp(row.get("date"), EpochType.UNIX_SECONDS)
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Telegram Message",
                    source_file=rel_path,
                    record_id=str(row.get("mid")),
                    timestamp=ts,
                    summary=f"[Telegram {direction}] {peer_name}: {body[:80]}",
                    attributes={
                        "dialog_uid": uid,
                        "peer_name": peer_name,
                        "direction": direction,
                        "read_state": int(row.get("read_state") or 0),
                        "body": body,
                    },
                )
            )
        return records
