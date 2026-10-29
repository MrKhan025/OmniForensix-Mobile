"""iOS binary and XML property list (.plist) parser for Wi-Fi networks and system metadata."""

from __future__ import annotations

import plistlib
from datetime import datetime
from pathlib import Path

from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosPlistConfigsPlugin(ArtifactPlugin):
    name = "ios_plist_configs"
    os_type = OSType.IOS
    category = "System Configuration"
    description = "Parses iOS binary/XML .plist files for Wi-Fi known networks and system build info"
    target_globs = ("*com.apple.wifi.plist", "*SystemVersion.plist", "*Info.plist")

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        try:
            with file_path.open("rb") as fh:
                plist_data = plistlib.load(fh)
        except Exception:
            return []

        if not isinstance(plist_data, dict):
            return []

        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))

        # Check for Wi-Fi networks list
        wifi_list = plist_data.get("List of known networks")
        if isinstance(wifi_list, list):
            for idx, net in enumerate(wifi_list, start=1):
                if not isinstance(net, dict):
                    continue
                ssid = str(net.get("SSID_STR") or "Hidden SSID")
                bssid = str(net.get("BSSID") or "Unknown")
                last_joined = net.get("lastJoined") or net.get("lastAutoJoined")
                ts = None
                if isinstance(last_joined, datetime):
                    ts = normalize_timestamp(last_joined.isoformat(), EpochType.ISO8601_STRING)
                records.append(
                    ArtifactRecord(
                        plugin_name=self.name,
                        os_type=self.os_type,
                        category="Network & Wi-Fi",
                        artifact_type="Known Wi-Fi Network",
                        source_file=rel_path,
                        record_id=f"wifi_{idx}",
                        timestamp=ts,
                        summary=f"Wi-Fi SSID '{ssid}' (BSSID {bssid})",
                        attributes={
                            "ssid": ssid,
                            "bssid": bssid,
                            "enabled": bool(net.get("enabled", True)),
                        },
                    )
                )
            return records

        # Generic SystemVersion / Info.plist record
        prod_version = plist_data.get("ProductVersion") or plist_data.get("CFBundleShortVersionString")
        bundle_id = plist_data.get("CFBundleIdentifier") or plist_data.get("ProductName")
        if prod_version or bundle_id:
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="Plist Metadata",
                    source_file=rel_path,
                    record_id=file_path.name,
                    timestamp=None,
                    summary=f"Plist {file_path.name}: {bundle_id} v{prod_version}",
                    attributes={
                        "bundle_id": str(bundle_id or ""),
                        "version": str(prod_version or ""),
                        "build_version": str(plist_data.get("ProductBuildVersion") or ""),
                    },
                )
            )
        return records
