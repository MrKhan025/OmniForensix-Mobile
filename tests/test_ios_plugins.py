"""Unit tests for iOS artifact plugins (iMessage/SMS, CallHistory, Safari, KnowledgeC, Plists)."""

from pathlib import Path
from omniforensix.plugins.ios.call_history import IosCallHistoryPlugin
from omniforensix.plugins.ios.imessage_sms import IosImessageSmsPlugin
from omniforensix.plugins.ios.plist_configs import IosPlistConfigsPlugin


def test_ios_imessage_sms_parser(synthetic_evidence_dir: Path) -> None:
    records = IosImessageSmsPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["address"] == "user@icloud.com"
    assert records[0].timestamp is not None
    assert records[0].timestamp.utc_iso8601 == "2023-11-14T22:13:20.000000Z"


def test_ios_call_history_parser(synthetic_evidence_dir: Path) -> None:
    records = IosCallHistoryPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["address"] == "+15550999"
    assert records[0].attributes["direction"] == "Outgoing"


def test_ios_wifi_plist_parser(synthetic_evidence_dir: Path) -> None:
    records = IosPlistConfigsPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["ssid"] == "Corp-Guest-5G"
