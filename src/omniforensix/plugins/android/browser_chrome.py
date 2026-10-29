"""Android Chrome / WebView browsing history parser."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class AndroidChromeHistoryPlugin(ArtifactPlugin):
    name = "android_chrome_history"
    os_type = OSType.ANDROID
    category = "Web Browser"
    description = "Parses visited URLs and WebKit timestamps from Android Chrome History SQLite DB"
    target_globs = ("*History", "*chrome_history.db")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "urls"):
            return []

        rows = execute_readonly_query(
            file_path,
            """
            SELECT id, url, title, visit_count, typed_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time ASC;
            """,
        )
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            url = str(row.get("url") or "")
            title = str(row.get("title") or "")
            domain = urlparse(url).hostname or ""
            ts = normalize_timestamp(row.get("last_visit_time"), EpochType.WEBKIT_MICROS)
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Browser History Visit",
                    source_file=rel_path,
                    record_id=str(row.get("id")),
                    timestamp=ts,
                    summary=f"Visited {url} ({title})",
                    attributes={
                        "url": url,
                        "domain": domain,
                        "title": title,
                        "visit_count": int(row.get("visit_count") or 0),
                        "typed_count": int(row.get("typed_count") or 0),
                    },
                )
            )
        return records
