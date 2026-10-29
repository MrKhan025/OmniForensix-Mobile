# OmniForensix-Mobile

**Open-Source Cross-Platform Mobile Digital Forensics & Artifact Analysis Toolkit (Android & iOS)**

`OmniForensix-Mobile` is a modular, forensically sound Python framework for analyzing **authorized, post-acquisition mobile forensic extractions, logical backups, and file system dumps** from Android and iOS devices.

> **Legal & Ethical Scope**: This toolkit operates strictly on pre-acquired backups and authorized forensic extractions. It contains zero lockscreen bypasses, bootloader exploits, or unauthorized extraction payloads.

## Architecture Overview

```mermaid
graph TD
    A[Evidence Source: .zip / .tar / .ab / iOS Manifest.db] --> B[Streaming SHA-256 / SHA-512 Sealer]
    B --> C[Hash-Chained Chain of Custody Ledger]
    B --> D[Safe Ingestion Engine & iOS Path Resolver]
    D --> E[Read-Only SQLite & Plist Plugin Registry]
    E --> F[Android Plugins: SMS, Calls, Chrome, Packages, UsageStats]
    E --> G[iOS Plugins: iMessage, CallHistory, Safari, KnowledgeC, Plists]
    F --> H[UTC ISO-8601 Super-Timeline Builder]
    G --> H
    F --> I[STIX / YAML IoC Threat & Stalkerware Scanner]
    G --> I
    D --> J[EXIF GPS & Magic-Byte Signature Carver]
    H --> K[Offline HTML5 Report + CSV / Timesketch JSONL]
    I --> K
    J --> K
```

## Quick Start

```bash
pip install -e ".[dev]"
omniforensix /path/to/backup --case-dir ./case_001 --case-id CASE-2026-01 --examiner "A. Investigator"
pytest
```
