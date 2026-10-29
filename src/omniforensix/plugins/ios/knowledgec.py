"""iOS knowledgeC.db (CoreDuet) activity and foreground app execution parser."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosKnowledgeCPlugin(ArtifactPlugin):
    name = "ios_knowledgec"
    os_type = OSType.IOS
    category = "Application Activity"
    description = "Parses iOS knowledgeC.db ZOBJECT records for app foreground usage and device lock states"
    target_globs = ("*knowledgeC.db",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "ZOBJECT"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT
                Z_PK,
                ZSTREAMNAME,
                ZVALUESTRING,
                ZSTARTDATE,
                ZENDDATE,
                ZCREATIONDATE
            FROM ZOBJECT
            ORDER BY ZSTARTDATE ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            stream = str(row.get("ZSTREAMNAME") or "")
            val_str = str(row.get("ZVALUESTRING") or "")
            start_raw = row.get("ZSTARTDATE")
            end_raw = row.get("ZENDDATE")
            ts = normalize_timestamp(start_raw, EpochType.MAC_ABSOLUTE_SECONDS)
            duration = (
                float(end_raw) - float(start_raw)
                if start_raw is not None and end_raw is not None
                else 0.0
            )
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="KnowledgeC Event",
                    source_file=rel_path,
                    record_id=str(row.get("Z_PK")),
                    timestamp=ts,
                    summary=f"KnowledgeC [{stream}] {val_str} ({duration:.1f}s)",
                    attributes={
                        "stream_name": stream,
                        "bundle_id": val_str,
                        "package_name": val_str,
                        "duration_seconds": duration,
                    },
                )
            )
        return records
