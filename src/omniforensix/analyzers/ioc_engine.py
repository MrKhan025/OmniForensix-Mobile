"""Indicator of Compromise (IoC) Threat Scanner supporting YAML and STIX-compatible watchlists."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field

from omniforensix.core.hashing import FileHashDigest
from omniforensix.plugins.base import ArtifactRecord

URL_DOMAIN_REGEX = re.compile(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", re.IGNORECASE)


class IoCWatchlist(BaseModel):
    """Structured threat intelligence watchlist for stalkerware, spyware, and phishing IoCs."""

    feed_name: str = "Default Mobile Threat Feed"
    malicious_domains: set[str] = Field(default_factory=set)
    malicious_ips: set[str] = Field(default_factory=set)
    stalkerware_packages: set[str] = Field(default_factory=set)
    malicious_sha256: set[str] = Field(default_factory=set)


class IoCMatch(BaseModel):
    """Single detected Indicator of Compromise hit against an artifact or file."""

    severity: str
    ioc_type: str
    matched_indicator: str
    source_plugin: str
    source_file: str
    record_id: str
    context_summary: str


DEFAULT_IOC_WATCHLIST = IoCWatchlist(
    feed_name="Built-in Stalkerware & Phishing Baseline",
    malicious_domains={"c2-stalker-sync.net", "mspy-update-portal.org", "verify-bank-alert.top"},
    malicious_ips={"198.51.100.214", "203.0.113.88"},
    stalkerware_packages={
        "com.mspy.tracker",
        "com.flexispy.main",
        "com.cerberus.stealth",
        "org.stalkerware.hiddenagent",
    },
    malicious_sha256={
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855_bad"
    },
)


def load_ioc_watchlist(watchlist_path: Path | None = None) -> IoCWatchlist:
    """Load a YAML/JSON IoC watchlist file or return the built-in mobile threat baseline."""
    if watchlist_path is None or not watchlist_path.exists():
        return DEFAULT_IOC_WATCHLIST

    raw: dict[str, Any] = yaml.safe_load(watchlist_path.read_text(encoding="utf-8")) or {}
    return IoCWatchlist(
        feed_name=str(raw.get("feed_name", watchlist_path.name)),
        malicious_domains={d.lower() for d in raw.get("malicious_domains", [])},
        malicious_ips=set(raw.get("malicious_ips", [])),
        stalkerware_packages={p.lower() for p in raw.get("stalkerware_packages", [])},
        malicious_sha256={h.lower() for h in raw.get("malicious_sha256", [])},
    )


def scan_artifacts_for_iocs(
    records: list[ArtifactRecord],
    file_digests: list[FileHashDigest] | None = None,
    watchlist: IoCWatchlist | None = None,
) -> list[IoCMatch]:
    """Cross-reference parsed artifacts and file hashes against the IoC watchlist."""
    active_watchlist = watchlist or DEFAULT_IOC_WATCHLIST
    matches: list[IoCMatch] = []

    # 1. Check file SHA-256 hashes
    if file_digests:
        for digest in file_digests:
            if digest.sha256.lower() in active_watchlist.malicious_sha256:
                matches.append(
                    IoCMatch(
                        severity="CRITICAL",
                        ioc_type="file_sha256",
                        matched_indicator=digest.sha256,
                        source_plugin="core_hashing",
                        source_file=digest.relative_path,
                        record_id=digest.relative_path,
                        context_summary=f"Known malicious file hash detected: {digest.relative_path}",
                    )
                )

    # 2. Check artifact attributes (packages, domains, SMS links, IP addresses)
    for rec in records:
        attrs = rec.attributes
        pkg = str(attrs.get("package_name") or attrs.get("bundle_id") or "").lower()
        if pkg and pkg in active_watchlist.stalkerware_packages:
            matches.append(
                IoCMatch(
                    severity="CRITICAL",
                    ioc_type="stalkerware_package",
                    matched_indicator=pkg,
                    source_plugin=rec.plugin_name,
                    source_file=rec.source_file,
                    record_id=rec.record_id,
                    context_summary=rec.summary,
                )
            )

        domain = str(attrs.get("domain") or "").lower()
        if domain and domain in active_watchlist.malicious_domains:
            matches.append(
                IoCMatch(
                    severity="HIGH",
                    ioc_type="malicious_domain",
                    matched_indicator=domain,
                    source_plugin=rec.plugin_name,
                    source_file=rec.source_file,
                    record_id=rec.record_id,
                    context_summary=rec.summary,
                )
            )

        # Extract URLs embedded inside SMS/iMessage bodies
        body = str(attrs.get("body") or "")
        for url_match in URL_DOMAIN_REGEX.finditer(body):
            extracted_domain = url_match.group(1).lower()
            if extracted_domain in active_watchlist.malicious_domains:
                matches.append(
                    IoCMatch(
                        severity="HIGH",
                        ioc_type="sms_phishing_domain",
                        matched_indicator=extracted_domain,
                        source_plugin=rec.plugin_name,
                        source_file=rec.source_file,
                        record_id=rec.record_id,
                        context_summary=rec.summary,
                    )
                )

    return matches
