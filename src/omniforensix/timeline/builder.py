"""Chronological Super-Timeline builder with CSV, JSONL, and Timesketch exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any
from pydantic import BaseModel

from omniforensix.plugins.base import ArtifactRecord


class TimelineEvent(BaseModel):
    """Normalized chronological event suitable for Timesketch and forensic timeline analysis."""

    datetime: str
    timestamp_desc: str
    unix_epoch: float
    os_type: str
    plugin: str
    category: str
    artifact_type: str
    source_file: str
    record_id: str
    message: str
    raw_timestamp: str
    attributes: dict[str, Any]


def build_super_timeline(records: list[ArtifactRecord]) -> list[TimelineEvent]:
    """Filter and sort all timestamped ArtifactRecords into strict chronological order."""
    events: list[TimelineEvent] = []
    for rec in records:
        if rec.timestamp is None:
            continue
        events.append(
            TimelineEvent(
                datetime=rec.timestamp.utc_iso8601,
                timestamp_desc=f"{rec.artifact_type} ({rec.timestamp.epoch_type.value})",
                unix_epoch=rec.timestamp.unix_epoch_seconds,
                os_type=rec.os_type.value,
                plugin=rec.plugin_name,
                category=rec.category,
                artifact_type=rec.artifact_type,
                source_file=rec.source_file,
                record_id=rec.record_id,
                message=rec.summary,
                raw_timestamp=str(rec.timestamp.raw_value),
                attributes=rec.attributes,
            )
        )
    events.sort(key=lambda e: e.unix_epoch)
    return events


def export_timeline_csv(events: list[TimelineEvent], output_csv: Path) -> Path:
    """Export the chronological timeline to a standard CSV file."""
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "datetime",
        "timestamp_desc",
        "os_type",
        "plugin",
        "category",
        "artifact_type",
        "source_file",
        "record_id",
        "message",
        "raw_timestamp",
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events:
            row = (ev.model_dump() if hasattr(ev, "model_dump") else ev.dict())
            writer.writerow({k: row[k] for k in fieldnames})
    return output_csv


def export_timeline_jsonl(events: list[TimelineEvent], output_jsonl: Path) -> Path:
    """Export the chronological timeline to a Timesketch-compatible JSONL file."""
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with output_jsonl.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps((ev.model_dump() if hasattr(ev, "model_dump") else ev.dict()), sort_keys=True) + "\n")
    return output_jsonl
