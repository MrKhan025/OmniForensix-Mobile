"""iOS SMS and iMessage database parser (sms.db)."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosImessageSmsPlugin(ArtifactPlugin):
    name = "ios_imessage_sms"
    os_type = OSType.IOS
    category = "Messaging"
    description = "Parses iOS sms.db for iMessage and SMS conversations with Cocoa nanosecond/second timestamps"
    target_globs = ("*sms.db",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "message"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT
                m.ROWID as row_id,
                m.guid as guid,
                m.text as text,
                m.service as service,
                m.is_from_me as is_from_me,
                m.date as date_raw,
                m.date_read as date_read_raw,
                h.id as handle_id
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            ORDER BY m.date ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            date_raw = row.get("date_raw") or 0
            # Modern iOS stores sms.db dates in Mac Absolute Nanoseconds (>1e14), older iOS in seconds
            epoch_type = (
                EpochType.MAC_ABSOLUTE_NANOS if float(date_raw) > 1e12 else EpochType.MAC_ABSOLUTE_SECONDS
            )
            ts = normalize_timestamp(date_raw, epoch_type)
            direction = "Sent" if row.get("is_from_me") else "Received"
            handle_id = str(row.get("handle_id") or "Unknown")
            text = str(row.get("text") or "")
            service = str(row.get("service") or "SMS")

            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type=f"iOS {service} Message",
                    source_file=rel_path,
                    record_id=str(row.get("row_id")),
                    timestamp=ts,
                    summary=f"[{service} {direction}] {handle_id}: {text[:80]}",
                    attributes={
                        "guid": row.get("guid"),
                        "address": handle_id,
                        "service": service,
                        "direction": direction,
                        "body": text,
                    },
                )
            )
        return records
