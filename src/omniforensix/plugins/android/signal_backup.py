"""Signal Private Messenger decrypted database parser (signal.db / signal_backup.db)."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class SignalBackupPlugin(ArtifactPlugin):
    name = "signal_backup_parser"
    os_type = OSType.CROSS_PLATFORM
    category = "Third-Party Messaging"
    description = "Parses decrypted Signal databases (signal.db / signal_backup.db) for messages, recipients, and disappearing timers"
    target_globs = ("*signal.db", "*signal_backup.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "message") and not table_exists(file_path, "sms"):
            return []

        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        # Build recipient lookup map if recipient table is present
        recipients: dict[int, str] = {}
        if table_exists(file_path, "recipient"):
            for r in execute_readonly_query(
                file_path,
                "SELECT _id, e164, system_joined_name, profile_given_name FROM recipient;",
            ):
                rid = int(r.get("_id") or 0)
                label = r.get("system_joined_name") or r.get("profile_given_name") or r.get("e164") or f"recipient:{rid}"
                recipients[rid] = str(label)

        table_name = "message" if table_exists(file_path, "message") else "sms"
        rows = execute_readonly_query(
            file_path,
            f"""
            SELECT
                _id,
                thread_id,
                from_recipient_id,
                date_sent,
                date_received,
                body,
                expires_in
            FROM {table_name}
            ORDER BY date_sent ASC;
            """,  # noqa: S608
        )
        for row in rows:
            sender_id = int(row.get("from_recipient_id") or 0)
            sender = recipients.get(sender_id, f"recipient:{sender_id}")
            body = str(row.get("body") or "")
            expires_ms = int(row.get("expires_in") or 0)
            ts = normalize_timestamp(row.get("date_sent") or row.get("date_received"), EpochType.UNIX_MILLIS)
            ephemeral_tag = f" [Disappearing: {expires_ms // 1000}s]" if expires_ms > 0 else ""

            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Signal Message",
                    source_file=rel_path,
                    record_id=str(row.get("_id")),
                    timestamp=ts,
                    summary=f"[Signal]{ephemeral_tag} {sender}: {body[:80]}",
                    attributes={
                        "thread_id": row.get("thread_id"),
                        "sender": sender,
                        "body": body,
                        "disappearing_timer_ms": expires_ms,
                        "date_received_raw": row.get("date_received"),
                    },
                )
            )
        return records
