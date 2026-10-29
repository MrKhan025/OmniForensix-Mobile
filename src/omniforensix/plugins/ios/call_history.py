"""iOS CallHistory.storedata SQLite parser."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosCallHistoryPlugin(ArtifactPlugin):
    name = "ios_call_history"
    os_type = OSType.IOS
    category = "Call Logs"
    description = "Parses iOS CallHistory.storedata (ZCALLRECORD) for phone and FaceTime call records"
    target_globs = ("*CallHistory.storedata",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "ZCALLRECORD"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT
                Z_PK,
                ZADDRESS,
                ZDURATION,
                ZDATE,
                ZORIGINATED,
                ZANSWERED,
                ZSERVICE_PROVIDER
            FROM ZCALLRECORD
            ORDER BY ZDATE ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            ts = normalize_timestamp(row.get("ZDATE"), EpochType.MAC_ABSOLUTE_SECONDS)
            address = row.get("ZADDRESS")
            if isinstance(address, bytes):
                address = address.decode("utf-8", errors="replace")
            address_str = str(address or "Unknown")
            duration = float(row.get("ZDURATION") or 0.0)
            direction = "Outgoing" if row.get("ZORIGINATED") else "Incoming"
            provider = str(row.get("ZSERVICE_PROVIDER") or "Telephony")

            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="iOS Call Record",
                    source_file=rel_path,
                    record_id=str(row.get("Z_PK")),
                    timestamp=ts,
                    summary=f"[{provider}] {direction} call with {address_str} ({duration:.1f}s)",
                    attributes={
                        "address": address_str,
                        "direction": direction,
                        "answered": bool(row.get("ZANSWERED")),
                        "duration_seconds": duration,
                        "service_provider": provider,
                    },
                )
            )
        return records
