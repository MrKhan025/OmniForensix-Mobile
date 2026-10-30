"""Unit tests for Android artifact plugins (SMS, Calls, Chrome, Packages, UsageStats)."""

from pathlib import Path
from omniforensix.plugins.android.browser_chrome import AndroidChromeHistoryPlugin
from omniforensix.plugins.android.calls_contacts import AndroidCallsContactsPlugin
from omniforensix.plugins.android.packages import AndroidPackagesPlugin
from omniforensix.plugins.android.sms_mms import AndroidSmsMmsPlugin


def test_android_sms_mms_parser(synthetic_evidence_dir: Path) -> None:
    records = AndroidSmsMmsPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["address"] == "+15550199"
    assert records[0].attributes["body"] == "Urgent alert: https://phishing.example.org/login"


def test_android_calls_contacts_parser(synthetic_evidence_dir: Path) -> None:
    records = AndroidCallsContactsPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["duration_seconds"] == 145
    assert records[0].attributes["call_type"] == "Incoming"


def test_android_chrome_history_parser(synthetic_evidence_dir: Path) -> None:
    records = AndroidChromeHistoryPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["domain"] == "c2.example.com"
    assert records[0].attributes["url"] == "https://c2.example.com/beacon"


def test_android_packages_xml_parser(synthetic_evidence_dir: Path) -> None:
    records = AndroidPackagesPlugin().run(synthetic_evidence_dir)
    assert len(records) == 1
    assert records[0].attributes["package_name"] == "com.mspy.tracker"
    assert "android.permission.READ_SMS" in records[0].attributes["granted_permissions"]
