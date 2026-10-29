"""iOS WhatsApp parser for ChatStorage.sqlite (ZWAMESSAGE and ZWACHATSESSION)."""

from __future__ import annotations

from pathlib import Path

from omniforensix.core.sqlite_utils import execute_readonly_query, table_exists
from omniforensix.core.timestamps import EpochType, normalize_timestamp
from omniforensix.plugins.base import ArtifactPlugin, ArtifactRecord, OSType, register_plugin


@register_plugin
class IosWhatsAppPlugin(ArtifactPlugin):
    name = "ios_whatsapp"
    os_type = OSType.IOS
    category = "Third-Party Messaging"
    description = "Parses iOS WhatsApp ChatStorage.sqlite (ZWAMESSAGE & ZWACHATSESSION) with Cocoa timestamps"
    target_globs = ("*ChatStorage.sqlite",)

    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        if not table_exists(file_path, "ZWAMESSAGE"):
            return []

        has_sessions = table_exists(file_path, "ZWACHATSESSION")
        if has_sessions:
            sql = """
                SELECT
                    m.Z_PK AS msg_pk,
                    m.ZISFROMME AS is_from_me,
                    m.ZMESSAGEDATE AS msg_date,
                    m.ZTEXT AS text_body,
                    m.ZFROMJID AS from_jid,
                    m.ZTOJID AS to_jid,
                    s.ZPARTNERNAME AS partner_name
                FROM ZWAMESSAGE m
                LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
                ORDER BY m.ZMESSAGEDATE ASC;
            """
        else:
            sql = """
                SELECT
                    Z_PK AS msg_pk,
                    ZISFROMME AS is_from_me,
                    ZMESSAGEDATE AS msg_date,
                    ZTEXT AS text_body,
                    ZFROMJID AS from_jid,
                    ZTOJID AS to_jid,
                    NULL AS partner_name
                FROM ZWAMESSAGE
                ORDER BY ZMESSAGEDATE ASC;
            """

        rows = execute_readonly_query(file_path, sql)
        records: list[ArtifactRecord] = []
        rel_path = str(file_path.relative_to(workspace_dir))
        for row in rows:
            direction = "Sent" if row.get("is_from_me") else "Received"
            peer = str(row.get("to_jid") if row.get("is_from_me") else row.get("from_jid") or "unknown")
            partner = str(row.get("partner_name") or peer)
            body = str(row.get("text_body") or "")
            ts = normalize_timestamp(row.get("msg_date"), EpochType.MAC_ABSOLUTE_SECONDS)
            records.append(
                ArtifactRecord(
                    plugin_name=self.name,
                    os_type=self.os_type,
                    category=self.category,
                    artifact_type="WhatsApp Message (iOS)",
                    source_file=rel_path,
                    record_id=str(row.get("msg_pk")),
                    timestamp=ts,
                    summary=f"[WhatsApp iOS {direction}] {partner}: {body[:80]}",
                    attributes={
                        "partner_name": partner,
                        "from_jid": row.get("from_jid"),
                        "to_jid": row.get("to_jid"),
                        "direction": direction,
                        "body": body,
                    },
                )
            )
        return records
