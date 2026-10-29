"""Android Package Manager (packages.xml) parser for installed apps and permissions."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class AndroidPackagesPlugin(ArtifactPlugin):
    name = "android_packages_xml"
    os_type = OSType.ANDROID
    category = "Installed Applications"
    description = "Parses Android /data/system/packages.xml for package metadata, install timestamps, and permissions"
    target_globs = ("*packages.xml",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        try:
            tree = ET.parse(file_path)  # noqa: S314
        except ET.ParseError:
            return []

        root = tree.getroot()
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        for idx, pkg_elem in enumerate(root.findall("package"), start=1):
            pkg_name = pkg_elem.attrib.get("name", "unknown.package")
            code_path = pkg_elem.attrib.get("codePath", "")
            installer = pkg_elem.attrib.get("installer", "unknown")
            version_code = pkg_elem.attrib.get("version", "")

            # Android stores install time in hex or decimal milliseconds in ft/it/ut attributes
            it_raw = pkg_elem.attrib.get("it") or pkg_elem.attrib.get("ft")
            ts_ms: int | None = None
            if it_raw:
                try:
                    ts_ms = int(it_raw, 16) if any(c in it_raw.lower() for c in "abcdef") else int(it_raw)
                except ValueError:
                    ts_ms = None

            perms_elem = pkg_elem.find("perms")
            granted_perms: list[str] = []
            if perms_elem is not None:
                for item in perms_elem.findall("item"):
                    if item.attrib.get("granted", "true") == "true" and "name" in item.attrib:
                        granted_perms.append(item.attrib["name"])

            ts = normalize_timestamp(ts_ms, EpochType.UNIX_MILLIS) if ts_ms else None
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Installed Android Package",
                    source_file=rel_path,
                    record_id=f"{idx}:{pkg_name}",
                    timestamp=ts,
                    summary=f"Package {pkg_name} (installer={installer}, permissions={len(granted_perms)})",
                    attributes={
                        "package_name": pkg_name,
                        "code_path": code_path,
                        "installer": installer,
                        "version_code": version_code,
                        "granted_permissions": granted_perms,
                    },
                )
            )
        return records
