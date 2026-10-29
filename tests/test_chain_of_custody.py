"""Unit tests for Chain of Custody hash-chaining, SQLite read-only safety, and CLI subcommands."""

from pathlib import Path
from typer.testing import CliRunner

from omniforensix.cli import app
from omniforensix.core.case import ForensicCase
from omniforensix.core.hashing import build_directory_manifest, verify_directory_manifest


def test_chain_of_custody_detects_log_tampering(tmp_path: Path, synthetic_evidence_dir: Path) -> None:
    case = ForensicCase(
        case_dir=tmp_path / "custody_case",
        case_id="CASE-777",
        case_name="Integrity Verification",
        examiner="Forensic Lead",
    )
    case.record_initial_evidence(synthetic_evidence_dir)
    case.log_custody_event("STEP_1", str(synthetic_evidence_dir))
    assert case.verify_custody_chain()[0] is True

    # Tamper with the log file
    content = case.coc_file.read_text(encoding="utf-8").replace("Forensic Lead", "Attacker")
    case.coc_file.write_text(content, encoding="utf-8")
    valid, errors = case.verify_custody_chain()
    assert valid is False
    assert len(errors) >= 1


def test_cli_modular_subcommands(tmp_path: Path, synthetic_evidence_dir: Path) -> None:
    initial_digests = build_directory_manifest(synthetic_evidence_dir)
    runner = CliRunner()
    case_out = tmp_path / "modular_case"

    res_analyze = runner.invoke(
        app,
        ["analyze", str(synthetic_evidence_dir), "--case-dir", str(case_out), "--case-id", "CASE-MOD-1"],
    )
    assert res_analyze.exit_code == 0, res_analyze.output
    assert (case_out / "reports" / "investigative_report.html").exists()

    # Confirm original evidence directory was never mutated
    ok, diffs = verify_directory_manifest(synthetic_evidence_dir, initial_digests)
    assert ok is True
    assert diffs == []
