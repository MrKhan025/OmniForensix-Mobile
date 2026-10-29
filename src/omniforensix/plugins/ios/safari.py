"""iOS Safari History.db parser."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosSafariHistoryPlugin(ArtifactPlugin):
    name = "ios_safari_history"
    os_type = OSType.IOS
    category = "Web Browser"
    description = "Parses iOS Safari History.db (history_items and history_visits)"
    target_globs = ("*History.db", "*safari_history.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "history_items") or not table_exists(file_path, "history_visits"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT
                v.id as visit_id,
                i.url as url,
                i.visit_count as visit_count,
                v.title as title,
                v.visit_time as visit_time
            FROM history_visits v
            JOIN history_items i ON v.history_item = i.id
            ORDER BY v.visit_time ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            url = str(row.get("url") or "")
            title = str(row.get("title") or "")
            domain = urlparse(url).hostname or ""
            ts = normalize_timestamp(row.get("visit_time"), EpochType.MAC_ABSOLUTE_SECONDS)
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Safari Visit",
                    source_file=rel_path,
                    record_id=str(row.get("visit_id")),
                    timestamp=ts,
                    summary=f"Safari visited {url} ({title})",
                    attributes={
                        "url": url,
                        "domain": domain,
                        "title": title,
                        "visit_count": int(row.get("visit_count") or 0),
                    },
                )
            )
        return records
