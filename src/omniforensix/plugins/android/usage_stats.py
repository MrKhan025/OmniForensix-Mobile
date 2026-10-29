"""Android UsageStats XML parser for foreground/background application activity."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class AndroidUsageStatsPlugin(ArtifactPlugin):
    name = "android_usage_stats"
    os_type = OSType.ANDROID
    category = "Application Activity"
    description = "Parses Android UsageStats XML files for last time active and total foreground time"
    target_globs = ("*usagestats*.xml", "*usage-history.xml")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        try:
            tree = ET.parse(file_path)  # noqa: S314
        except ET.ParseError:
            return []

        root = tree.getroot()
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        for idx, pkg_elem in enumerate(root.findall(".//package"), start=1):
            pkg_name = pkg_elem.attrib.get("package") or pkg_elem.attrib.get("name") or "unknown"
            last_active_raw = pkg_elem.attrib.get("lastTimeActive") or pkg_elem.attrib.get("lastTimeVisible")
            total_time_fg = int(pkg_elem.attrib.get("timeActive") or 0)
            ts = normalize_timestamp(int(last_active_raw), EpochType.UNIX_MILLIS) if last_active_raw else None

            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="App Usage Record",
                    source_file=rel_path,
                    record_id=str(idx),
                    timestamp=ts,
                    summary=f"App {pkg_name} active for {total_time_fg}ms",
                    attributes={
                        "package_name": pkg_name,
                        "total_foreground_ms": total_time_fg,
                    },
                )
            )
        return records
