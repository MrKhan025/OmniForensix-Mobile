"""Typer CLI (`ingest`, `parse`, `timeline`, `ioc-scan`, `report`, `serve`, `analyze`) and FastAPI viewer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
import typer
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from rich.console import Console
from rich.table import Table

from omniforensix.analyzers.exif_carver import analyze_media_and_signatures, scan_sqlite_deleted_records
from omniforensix.analyzers.ioc_engine import IoCMatch, load_ioc_watchlist, scan_artifacts_for_iocs
from omniforensix.core.case import ForensicCase
from omniforensix.core.crypto_decryptor import auto_decrypt_workspace_databases, decrypt_whatsapp_crypt_file
from omniforensix.core.hashing import build_directory_manifest
from omniforensix.core.ingestion import ingest_evidence_source
from omniforensix.plugins.base import ArtifactRecord, OSType, get_registered_plugins
from omniforensix.reporting.html_generator import generate_html_report
from omniforensix.timeline.builder import (
    build_super_timeline,
    export_timeline_csv,
    export_timeline_jsonl,
)

app = typer.Typer(
    name="omniforensix",
    help="Open-source cross-platform mobile forensics and artifact analysis toolkit (Android & iOS).",
    add_completion=False,
)
console = Console()


def _load_records(case_dir: Path) -> list[ArtifactRecord]:
    records_file = case_dir / "reports" / "parsed_artifacts.json"
    if not records_file.exists():
        return []
    raw_list = json.loads(records_file.read_text(encoding="utf-8"))
    return [ArtifactRecord.model_validate(item) for item in raw_list]


@app.command("ingest")
def cmd_ingest(
    evidence_path: Path = typer.Argument(..., exists=True, help="Source backup archive or extraction folder"),
    case_dir: Path = typer.Option(..., "--case-dir", "-o", help="Case workspace directory"),
    case_id: str = typer.Option("CASE-001", "--case-id", help="Forensic case ID"),
    case_name: str = typer.Option("Mobile Investigation", "--case-name", help="Case name"),
    examiner: str = typer.Option("DFIR Analyst", "--examiner", help="Examiner name"),
) -> None:
    """Ingest evidence archive/folder, seal SHA-256/SHA-512 hashes, and initialize Chain of Custody."""
    case = ForensicCase(case_dir=case_dir, case_id=case_id, case_name=case_name, examiner=examiner)
    case.record_initial_evidence(evidence_path)
    ingested = ingest_evidence_source(evidence_path, case.workspace_dir)
    decrypted_dbs = auto_decrypt_workspace_databases(case.workspace_dir)
    case.log_custody_event(
        action="WORKSPACE_INGESTED",
        target_path=str(case.workspace_dir),
        details={"ingested_file_count": len(ingested), "decrypted_db_count": len(decrypted_dbs)},
    )
    console.print(f"[green]Ingested {len(ingested)} files into {case.workspace_dir}[/green]")


@app.command("decrypt")
def cmd_decrypt(
    crypt_file: Path = typer.Argument(..., exists=True, help="Path to .db.crypt14 or .db.crypt15 file"),
    key_source: str = typer.Option(..., "--key", "-k", help="Path to 158-byte key file or 64-digit hex key"),
    output_db: Optional[Path] = typer.Option(None, "--output", "-o", help="Output decrypted .db path"),
) -> None:
    """Decrypt an Android WhatsApp .db.crypt14 or .db.crypt15 database using an authorized key file or 64-digit hex key."""
    res = decrypt_whatsapp_crypt_file(crypt_file, key_source, output_db)
    console.print(
        f"[green]Decrypted {res.encrypted_source} -> {res.decrypted_target} "
        f"({res.decrypted_size_bytes} bytes, {res.cipher_scheme})[/green]"
    )

@app.command("parse")
def cmd_parse(
    case_dir: Path = typer.Option(..., "--case-dir", "-o", exists=True, help="Case workspace directory"),
    os_filter: Optional[OSType] = typer.Option(None, "--os", help="Filter plugins by android or ios"),
    examiner: str = typer.Option("DFIR Analyst", "--examiner", help="Examiner name"),
) -> None:
    """Run registered Android and iOS artifact plugins on the ingested workspace."""
    case = ForensicCase(case_dir=case_dir, case_id="CASE-001", case_name="Mobile Investigation", examiner=examiner)
    plugins = get_registered_plugins(os_filter=os_filter)
    all_records: list[ArtifactRecord] = []
    for plugin in plugins:
        parsed = plugin.run(case.workspace_dir)
        if parsed:
            all_records.extend(parsed)
            case.log_custody_event(
                action=f"PLUGIN_EXECUTED:{plugin.name}",
                target_path=str(case.workspace_dir),
                details={"records_extracted": len(parsed)},
            )
    out_file = case.reports_dir / "parsed_artifacts.json"
    out_file.write_text(
        json.dumps([(r.model_dump(mode="json") if hasattr(r, "model_dump") else json.loads(r.json())) for r in all_records], indent=2),
        encoding="utf-8",
    )
    console.print(f"[green]Extracted {len(all_records)} artifact records -> {out_file}[/green]")


@app.command("timeline")
def cmd_timeline(
    case_dir: Path = typer.Option(..., "--case-dir", "-o", exists=True, help="Case workspace directory"),
) -> None:
    """Generate normalized UTC ISO-8601 Super-Timeline in CSV and Timesketch JSONL formats."""
    records = _load_records(case_dir)
    events = build_super_timeline(records)
    reports_dir = case_dir / "reports"
    csv_path = export_timeline_csv(events, reports_dir / "super_timeline.csv")
    jsonl_path = export_timeline_jsonl(events, reports_dir / "super_timeline.jsonl")
    console.print(f"[green]Built {len(events)} timeline events -> {csv_path} & {jsonl_path}[/green]")


@app.command("ioc-scan")
def cmd_ioc_scan(
    case_dir: Path = typer.Option(..., "--case-dir", "-o", exists=True, help="Case workspace directory"),
    ioc_file: Optional[Path] = typer.Option(None, "--ioc-file", help="Path to YAML IoC watchlist"),
) -> None:
    """Scan extracted artifacts and workspace file hashes against Threat Intelligence / Stalkerware IoCs."""
    records = _load_records(case_dir)
    digests = build_directory_manifest(case_dir / "extracted_evidence")
    watchlist = load_ioc_watchlist(ioc_file)
    matches = scan_artifacts_for_iocs(records, digests, watchlist)
    out_file = case_dir / "reports" / "ioc_matches.json"
    out_file.write_text(
        json.dumps([(m.model_dump(mode="json") if hasattr(m, "model_dump") else json.loads(m.json())) for m in matches], indent=2),
        encoding="utf-8",
    )
    console.print(f"[bold red]Detected {len(matches)} IoC matches -> {out_file}[/bold red]")


@app.command("report")
def cmd_report(
    case_dir: Path = typer.Option(..., "--case-dir", "-o", exists=True, help="Case workspace directory"),
    case_id: str = typer.Option("CASE-001", "--case-id", help="Case ID"),
    case_name: str = typer.Option("Mobile Investigation", "--case-name", help="Case name"),
    examiner: str = typer.Option("DFIR Analyst", "--examiner", help="Examiner name"),
) -> None:
    """Compile offline HTML5 investigative report from parsed artifacts, timeline, EXIF, and IoC findings."""
    records = _load_records(case_dir)
    events = build_super_timeline(records)
    media_findings = analyze_media_and_signatures(case_dir / "extracted_evidence")
    ioc_file = case_dir / "reports" / "ioc_matches.json"
    ioc_matches: list[IoCMatch] = []
    if ioc_file.exists():
        ioc_matches = [IoCMatch.model_validate(x) for x in json.loads(ioc_file.read_text(encoding="utf-8"))]
    else:
        ioc_matches = scan_artifacts_for_iocs(records, build_directory_manifest(case_dir / "extracted_evidence"))

    html_path = generate_html_report(
        output_path=case_dir / "reports" / "investigative_report.html",
        case_id=case_id,
        case_name=case_name,
        examiner=examiner,
        records=records,
        timeline=events,
        ioc_matches=ioc_matches,
        media_findings=media_findings,
    )
    console.print(f"[green]Generated HTML5 investigative report -> {html_path}[/green]")


@app.command("analyze")
def cmd_analyze(
    evidence_path: Path = typer.Argument(..., exists=True, help="Path to backup archive or logical extraction"),
    case_dir: Path = typer.Option(..., "--case-dir", "-o", help="Output directory for forensic case workspace"),
    case_id: str = typer.Option("CASE-001", "--case-id", help="Unique forensic case identifier"),
    case_name: str = typer.Option("Mobile Investigation", "--case-name", help="Descriptive case title"),
    examiner: str = typer.Option("DFIR Analyst", "--examiner", help="Investigator name for Chain of Custody"),
    os_filter: Optional[OSType] = typer.Option(None, "--os", help="Filter plugins by OS (android or ios)"),
    ioc_file: Optional[Path] = typer.Option(None, "--ioc-file", help="Custom YAML IoC watchlist"),
) -> None:
    """Execute the full pipeline (`ingest` -> `parse` -> `ioc-scan` -> `timeline` -> `report`) in one command."""
    cmd_ingest(evidence_path=evidence_path, case_dir=case_dir, case_id=case_id, case_name=case_name, examiner=examiner)
    cmd_parse(case_dir=case_dir, os_filter=os_filter, examiner=examiner)
    cmd_ioc_scan(case_dir=case_dir, ioc_file=ioc_file)
    cmd_timeline(case_dir=case_dir)
    cmd_report(case_dir=case_dir, case_id=case_id, case_name=case_name, examiner=examiner)

    sqlite_forensics = scan_sqlite_deleted_records(case_dir / "extracted_evidence")
    (case_dir / "reports" / "sqlite_wal_freelist_audit.json").write_text(
        json.dumps(sqlite_forensics, indent=2), encoding="utf-8"
    )

    records = _load_records(case_dir)
    table = Table(title=f"Forensic Summary — {case_id}")
    table.add_column("Stage", style="cyan")
    table.add_column("Result", style="green")
    table.add_row("Extracted Artifact Records", str(len(records)))
    table.add_row("SQLite Databases Audited", str(len(sqlite_forensics)))
    table.add_row("HTML5 Report", str(case_dir / "reports" / "investigative_report.html"))
    console.print(table)


def create_web_viewer_app(case_dir: Path) -> FastAPI:
    """Create a local read-only FastAPI inspection server for browsing reports and JSON endpoints."""
    web = FastAPI(title="OmniForensix Local Case Viewer", version="1.0.0")

    @web.get("/", response_class=HTMLResponse)
    def index() -> str:
        report_file = case_dir / "reports" / "investigative_report.html"
        if report_file.exists():
            return report_file.read_text(encoding="utf-8")
        return "<html><body><h1>Report not generated yet. Run `omniforensix report` first.</h1></body></html>"

    @web.get("/api/artifacts", response_class=JSONResponse)
    def api_artifacts() -> list[dict[str, object]]:
        return [(r.model_dump(mode="json") if hasattr(r, "model_dump") else json.loads(r.json())) for r in _load_records(case_dir)]

    return web


@app.command("serve")
def cmd_serve(
    case_dir: Path = typer.Option(..., "--case-dir", "-o", exists=True, help="Case workspace directory"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8080, "--port", help="Bind port"),
) -> None:
    """Launch the optional local FastAPI investigative web viewer."""
    import uvicorn

    web_app = create_web_viewer_app(case_dir)
    uvicorn.run(web_app, host=host, port=port)
