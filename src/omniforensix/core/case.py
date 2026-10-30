"""Forensic Case Management and cryptographically chained Chain of Custody audit ledger."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

from omniforensix.core.hashing import FileHashDigest, build_directory_manifest, compute_file_hashes


def _dump_model(model: Any) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        res: dict[str, Any] = model.model_dump(mode="json")
        return res
    return dict(model.dict())


class ChainOfCustodyEntry(BaseModel):
    """Single immutable entry in the hash-chained Chain of Custody log."""

    sequence: int
    timestamp_utc: str
    examiner: str
    action: str
    target_path: str
    details: dict[str, Any] = Field(default_factory=dict)
    previous_entry_hash: str
    entry_hash: str


class CaseMetadata(BaseModel):
    """Case configuration and initial evidence manifest."""

    case_id: str
    case_name: str
    examiner: str
    agency: str = "Independent DFIR Lab"
    created_utc: str
    source_evidence_path: str
    extracted_workspace_path: str
    evidence_digests: list[dict[str, Any]] = Field(default_factory=list)


class ForensicCase:
    """Manages case workspace directories, evidence integrity, and Chain of Custody logs."""

    def __init__(self, case_dir: Path, case_id: str, case_name: str, examiner: str) -> None:
        self.case_dir = case_dir.resolve()
        self.workspace_dir = self.case_dir / "extracted_evidence"
        self.reports_dir = self.case_dir / "reports"
        self.case_file = self.case_dir / "case_metadata.json"
        self.coc_file = self.case_dir / "chain_of_custody.jsonl"

        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.case_id = case_id
        self.case_name = case_name
        self.examiner = examiner

    def log_custody_event(
        self,
        action: str,
        target_path: str,
        details: dict[str, Any] | None = None,
    ) -> ChainOfCustodyEntry:
        """Append a cryptographically linked event to chain_of_custody.jsonl."""
        prev_hash = "0" * 64
        seq = 1

        if self.coc_file.exists():
            lines = [
                line.strip()
                for line in self.coc_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            if lines:
                last_obj = json.loads(lines[-1])
                prev_hash = str(last_obj["entry_hash"])
                seq = int(last_obj["sequence"]) + 1

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        safe_details: dict[str, Any] = details if details is not None else {}
        payload: dict[str, Any] = {
            "sequence": seq,
            "timestamp_utc": now_utc,
            "examiner": self.examiner,
            "action": action,
            "target_path": target_path,
            "details": safe_details,
            "previous_entry_hash": prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(canonical).hexdigest()

        entry = ChainOfCustodyEntry(
            sequence=seq,
            timestamp_utc=now_utc,
            examiner=self.examiner,
            action=action,
            target_path=target_path,
            details=safe_details,
            previous_entry_hash=prev_hash,
            entry_hash=entry_hash,
        )
        with self.coc_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(_dump_model(entry)) + "\n")
        return entry

    def verify_custody_chain(self) -> tuple[bool, list[str]]:
        """Verify that no entry in chain_of_custody.jsonl has been altered or reordered."""
        if not self.coc_file.exists():
            return True, []

        errors: list[str] = []
        prev_hash = "0" * 64
        lines = [
            line.strip()
            for line in self.coc_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

        for idx, line in enumerate(lines, start=1):
            data = json.loads(line)
            recorded_hash = data.pop("entry_hash", "")
            if data.get("sequence") != idx:
                errors.append(f"Sequence mismatch at line {idx}")
            if data.get("previous_entry_hash") != prev_hash:
                errors.append(f"Broken hash chain at sequence {idx}")

            canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recomputed = hashlib.sha256(canonical).hexdigest()
            if recomputed != recorded_hash:
                errors.append(f"Tampered entry detected at sequence {idx}")
            prev_hash = recorded_hash

        return (len(errors) == 0, errors)

    def record_initial_evidence(self, source_path: Path) -> list[FileHashDigest]:
        """Hash source evidence (file or directory) and save case_metadata.json."""
        if source_path.is_file():
            digests = [compute_file_hashes(source_path)]
        else:
            digests = build_directory_manifest(source_path)

        meta = CaseMetadata(
            case_id=self.case_id,
            case_name=self.case_name,
            examiner=self.examiner,
            created_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            source_evidence_path=str(source_path.resolve()),
            extracted_workspace_path=str(self.workspace_dir),
            evidence_digests=[d.to_dict() for d in digests],
        )
        self.case_file.write_text(json.dumps(_dump_model(meta), indent=2), encoding="utf-8")
        self.log_custody_event(
            action="EVIDENCE_HASH_SEALED",
            target_path=str(source_path),
            details={
                "file_count": len(digests),
                "primary_sha256": digests[0].sha256 if digests else "",
            },
        )
        return digests
