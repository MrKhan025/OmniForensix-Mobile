"""Unit tests for WhatsApp (Android & iOS), Telegram, and Signal forensic parsers."""

from pathlib import Path
from urllib.parse import urlparse
from omniforensix.plugins.android.signal_backup import SignalBackupPlugin
from omniforensix.plugins.android.telegram import TelegramCachePlugin
from omniforensix.plugins.android.whatsapp import AndroidWhatsAppPlugin
from omniforensix.plugins.ios.whatsapp_ios import IosWhatsAppPlugin


def test_android_whatsapp_msgstore_and_wadb(synthetic_evidence_dir: Path) -> None:
    records = AndroidWhatsAppPlugin().run(synthetic_evidence_dir)
    assert len(records) == 2
    types = {r.artifact_type for r in records}
    assert "WhatsApp Message (Android)" in types
    assert "WhatsApp Contact" in types


def test_ios_whatsapp_chatstorage(synthetic_evidence_dir: Path) -> None:
    records = IosWhatsAppPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["partner_name"] == "Alice Witness"
    assert records[0].attributes["body"] == "Encrypted drop coordinates attached"


def test_telegram_cache4_parser(synthetic_evidence_dir: Path) -> None:
    records = TelegramCachePlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["peer_name"] == "Telegram Handler"
    extracted_url = str(records[0].attributes["body"]).strip()
    assert extracted_url == "https://c2.example.com/payload"
    assert urlparse(extracted_url).hostname == "c2.example.com"


def test_signal_decrypted_backup_parser(synthetic_evidence_dir: Path) -> None:
    records = SignalBackupPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["sender"] == "Bob Informant"
    assert records[0].attributes["disappearing_timer_ms"] == 60000
