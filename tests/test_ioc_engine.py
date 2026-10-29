"""Unit tests for the YAML/STIX Indicator of Compromise (IoC) threat scanner."""

from pathlib import Path
from omniforensix.analyzers.ioc_engine import scan_artifacts_for_iocs
from omniforensix.plugins.base import get_registered_plugins


def test_ioc_engine_detects_all_three_threat_vectors(synthetic_evidence_dir: Path) -> None:
    records = []
    for plugin in get_registered_plugins():
        records.extend(plugin.run(synthetic_evidence_dir))

    matches = scan_artifacts_for_iocs(records)
    ioc_types = {m.ioc_type for m in matches}
    assert "stalkerware_package" in ioc_types
    assert "malicious_domain" in ioc_types
    assert "sms_phishing_domain" in ioc_types
