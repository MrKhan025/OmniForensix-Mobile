"""Android WhatsApp parser supporting msgstore.db (modern & legacy schemas) and wa.db contacts."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class AndroidWhatsAppPlugin(ArtifactPlugin):
    name = "android_whatsapp"
    os_type = OSType.ANDROID
    category = "Third-Party Messaging"
    description = "Parses Android WhatsApp msgstore.db (modern message/jid and legacy messages tables) and wa.db contacts"
    target_globs = ("*msgstore.db", "*wa.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        # 1. Modern msgstore.db schema (message + chat + jid)
        if table_exists(file_path, "message") and table_exists(file_path, "jid"):
            rows = execute_readonly_query(
                file_path,
                """
                SELECT
                    m._id AS msg_id,
                    m.from_me AS from_me,
                    m.timestamp AS ts_ms,
                    m.text_data AS text_data,
                    m.message_type AS message_type,
                    j.raw_string AS chat_jid
                FROM message m
                LEFT JOIN chat c ON m.chat_row_id = c._id
                LEFT JOIN jid j ON c.jid_row_id = j._id
                ORDER BY m.timestamp ASC;
                """,
            )
            for row in rows:
                direction = "Sent" if row.get("from_me") else "Received"
                chat_jid = str(row.get("chat_jid") or "unknown@s.whatsapp.net")
                body = str(row.get("text_data") or "")
                ts = normalize_timestamp(row.get("ts_ms"), EpochType.UNIX_MILLIS)
                records.append(
                    ArtifactRecord(
                        plugin_name=self.name,
                        os_type=self.os_type,
                        category=self.category,
                        artifact_type="WhatsApp Message (Android)",
                        source_file=rel_path,
                        record_id=f"msg_{row.get('msg_id')}",
                        timestamp=ts,
                        summary=f"[WhatsApp {direction}] {chat_jid}: {body[:80]}",
                        attributes={
                            "chat_jid": chat_jid,
                            "direction": direction,
                            "message_type": int(row.get("message_type") or 0),
                            "body": body,
                        },
                    )
                )
            return records

        # 2. Legacy msgstore.db schema (messages table)
        if table_exists(file_path, "messages"):
            rows = execute_readonly_query(
                file_path,
                """
                SELECT
                    _id,
                    key_remote_jid,
                    key_from_me,
                    data,
                    timestamp,
                    media_url,
                    media_mime_type,
                    latitude,
                    longitude
                FROM messages
                ORDER BY timestamp ASC;
                """,
            )
            for row in rows:
                direction = "Sent" if row.get("key_from_me") else "Received"
                jid = str(row.get("key_remote_jid") or "unknown@s.whatsapp.net")
                body = str(row.get("data") or "")
                ts = normalize_timestamp(row.get("timestamp"), EpochType.UNIX_MILLIS)
                records.append(
                    ArtifactRecord(
                        plugin_name=self.name,
                        os_type=self.os_type,
                        category=self.category,
                        artifact_type="WhatsApp Message (Legacy Android)",
                        source_file=rel_path,
                        record_id=f"legacy_msg_{row.get('_id')}",
                        timestamp=ts,
                        summary=f"[WhatsApp {direction}] {jid}: {body[:80]}",
                        attributes={
                            "chat_jid": jid,
                            "direction": direction,
                            "body": body,
                            "media_url": row.get("media_url"),
                            "media_mime_type": row.get("media_mime_type"),
                            "latitude": row.get("latitude"),
                            "longitude": row.get("longitude"),
                        },
                    )
                )
            return records

        # 3. WhatsApp Contacts database (wa.db -> wa_contacts)
        if table_exists(file_path, "wa_contacts"):
            rows = execute_readonly_query(
                file_path,
                """
                SELECT _id, jid, display_name, number, status, status_timestamp
                FROM wa_contacts
                ORDER BY _id ASC;
                """,
            )
            for row in rows:
                jid = str(row.get("jid") or "")
                disp = str(row.get("display_name") or "")
                num = str(row.get("number") or "")
                ts = normalize_timestamp(row.get("status_timestamp"), EpochType.UNIX_MILLIS)
                records.append(
                    ArtifactRecord(
                        plugin_name=self.name,
                        os_type=self.os_type,
                        category="Contacts & Accounts",
                        artifact_type="WhatsApp Contact",
                        source_file=rel_path,
                        record_id=f"contact_{row.get('_id')}",
                        timestamp=ts,
                        summary=f"WhatsApp Contact: {disp} ({num} / {jid})",
                        attributes={
                            "jid": jid,
                            "display_name": disp,
                            "number": num,
                            "status": row.get("status"),
                        },
                    )
                )
        return records
