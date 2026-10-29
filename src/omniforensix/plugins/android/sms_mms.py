"""Android SMS/MMS database parser (mmssms.db / bugle_db)."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin

SMS_TYPE_MAP = {
    1: "Inbox (Received)",
    2: "Sent",
    3: "Draft",
    4: "Outbox",
    5: "Failed",
    6: "Queued",
}


@register_plugin
class AndroidSmsMmsPlugin(ArtifactPlugin):
    name = "android_sms_mms"
    os_type = OSType.ANDROID
    category = "Messaging"
    description = "Parses SMS messages from Android Telephony provider mmssms.db"
    target_globs = ("*mmssms.db",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "sms"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT _id, thread_id, address, date, date_sent, read, type, body, service_center
            FROM sms
            ORDER BY date ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            direction = SMS_TYPE_MAP.get(int(row.get("type") or 0), "Unknown")
            ts = normalize_timestamp(row.get("date"), EpochType.UNIX_MILLIS)
            address = str(row.get("address") or "Unknown")
            body = str(row.get("body") or "")
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="SMS Message",
                    source_file=rel_path,
                    record_id=str(row.get("_id")),
                    timestamp=ts,
                    summary=f"[{direction}] {address}: {body[:80]}",
                    attributes={
                        "thread_id": row.get("thread_id"),
                        "address": address,
                        "direction": direction,
                        "read": bool(row.get("read")),
                        "body": body,
                        "service_center": row.get("service_center"),
                        "date_sent_raw": row.get("date_sent"),
                    },
                )
            )
        return records
