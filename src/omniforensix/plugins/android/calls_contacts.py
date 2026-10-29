"""Android Call Logs and Contacts parser (contacts2.db / calllog.db)."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin

CALL_TYPE_MAP = {
    1: "Incoming",
    2: "Outgoing",
    3: "Missed",
    4: "Voicemail",
    5: "Rejected",
    6: "Blocked",
}


@register_plugin
class AndroidCallsContactsPlugin(ArtifactPlugin):
    name = "android_calls_contacts"
    os_type = OSType.ANDROID
    category = "Call Logs"
    description = "Parses call history from Android contacts2.db and calllog.db"
    target_globs = ("*contacts2.db", "*calllog.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "calls"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT _id, number, date, duration, type, name, geocoded_location
            FROM calls
            ORDER BY date ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            call_type = CALL_TYPE_MAP.get(int(row.get("type") or 0), "Unknown")
            number = str(row.get("number") or "Unknown")
            duration = int(row.get("duration") or 0)
            ts = normalize_timestamp(row.get("date"), EpochType.UNIX_MILLIS)
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Phone Call",
                    source_file=rel_path,
                    record_id=str(row.get("_id")),
                    timestamp=ts,
                    summary=f"{call_type} call with {number} ({duration}s)",
                    attributes={
                        "number": number,
                        "call_type": call_type,
                        "duration_seconds": duration,
                        "cached_name": row.get("name"),
                        "geocoded_location": row.get("geocoded_location"),
                    },
                )
            )
        return records
