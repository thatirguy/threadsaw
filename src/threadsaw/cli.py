from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import MOTTO, PROJECT_NAME, __version__
from .attachments import export_attachment_run
from .case import load_case
from .case_context import (
    AUTH_FACTOR_IDS,
    RECEIVED_FACTOR_IDS,
    recompute_case_context,
    set_organization_domains,
)
from .db import connect_db, initialize_schema
from .doctor import run_doctor
from .exporter import export_messages
from .evaluate_email import evaluate_phishing_email
from .ingest import ingest_path
from .reports import write_reports, write_timestamped_reports
from .selection import create_scope, resolve_message_hashes
from .security import install_runtime_guardrails
from .urls import extract_urls, write_url_report, write_timestamped_url_report
from .progress import console_progress
from .string_search import run_string_search
from .qr import evaluate_qrs
from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .phish_hunt_presets import available_presets, preset_config
from .phish_hunt import (
    list_hunt_runs,
    load_scoring_config,
    read_hunt_report_selection,
    run_phish_hunt,
    selection_span_days,
)


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _add_selector(parser: argparse.ArgumentParser, *, require: bool = False) -> None:
    group = parser.add_mutually_exclusive_group(required=require)
    group.add_argument("--sha256", dest="one_sha256", help="SHA-256 of the indexed EML representation")
    group.add_argument("--sha256-csv", type=_path, help="CSV containing message_sha256 or sha256 values")
    group.add_argument("--scope", help="Named logical selection")
    group.add_argument("--all", action="store_true", dest="all_messages", help="Select every indexed message")
    parser.add_argument("--start", help="Start time, inclusive, ISO 8601 with offset/Z")
    parser.add_argument("--end", help="End time, exclusive, ISO 8601 with offset/Z")


def _add_phish_hunt_report_selector(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--phish-hunt-report",
        type=_path,
        help="Threadsaw phish_hunt.csv used only to select message hashes by score",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        help="Select messages whose uncapped integer Phish Hunt score is equal to or above this value",
    )


def _resolved_for_analysis(args, conn, case_dir: Path, *, require: bool = False) -> list[str]:
    report = getattr(args, "phish_hunt_report", None)
    min_score = getattr(args, "min_score", None)
    normal_requested = any((args.one_sha256, args.sha256_csv, args.scope, args.all_messages, args.start, args.end))
    if report:
        if normal_requested:
            raise ValueError("--phish-hunt-report cannot be combined with another message selector")
        if min_score is None:
            raise ValueError("--phish-hunt-report requires --min-score")
        case_id = str(load_case(case_dir)["case_id"])
        return read_hunt_report_selection(report, min_score=min_score, case_id=case_id, conn=conn)
    if min_score is not None:
        raise ValueError("--min-score requires --phish-hunt-report")
    if normal_requested:
        return _resolved(args, conn, require=True)
    if require:
        raise ValueError("A message selector is required")
    return [row["message_sha256"] for row in conn.execute(
        "SELECT message_sha256 FROM messages ORDER BY selected_date_utc,message_sha256"
    )]


def _resolved(args, conn, *, require: bool = True) -> list[str]:
    date_requested = bool(args.start or args.end)
    if require and not any((args.one_sha256, args.sha256_csv, args.scope, args.all_messages, date_requested)):
        raise ValueError("A selector is required: --sha256, --sha256-csv, --scope, --start/--end, or --all")
    return resolve_message_hashes(conn, one_sha256=args.one_sha256, sha256_csv=args.sha256_csv, start=args.start, end=args.end,
                       scope=args.scope, all_messages=args.all_messages or not require)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threadsaw", description=f"{PROJECT_NAME}: {MOTTO}")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress messages; final JSON output is still printed")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="Hash, extract, parse, and index PST/EML/optional MSG input")
    p.add_argument("--input", required=True, type=_path)
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--no-recursive", action="store_true")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--include-deleted", action="store_true", help="Pass readpst -D to include recoverable deleted PST items")
    p.add_argument("--allow-low-disk", action="store_true", help="Override PST disk-space preflight warning")
    p.add_argument("--disk-multiplier", type=float, default=5.0, help="Estimated case-space multiplier for PST preflight (default: 5.0)")
    p.add_argument(
        "--organization-domain",
        action="append",
        default=None,
        help="Analyst-declared organization domain for direction and lookalike context; repeat for multiple domains",
    )

    p = sub.add_parser("report", help="Export analyst-facing CSV/JSON reports")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output", type=_path)
    p.add_argument("--large-case", action="store_true", help="Stream outputs and write JSON Lines instead of a large JSON array")
    _add_selector(p, require=False)

    p = sub.add_parser("urls", help="Extract URL strings offline; never retrieve or follow them")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output", type=_path)
    _add_selector(p, require=False)
    _add_phish_hunt_report_selector(p)

    p = sub.add_parser("attachments", help="Report or copy attachment bytes; never launch or execute them")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output", required=True, type=_path)
    p.add_argument("--copy-files", action="store_true", help="Copy selected attachment bytes into the output tree")
    p.add_argument("--copy-output", type=_path, help="Optional separate folder for copied attachment bytes")
    p.add_argument("--list-zip-contents", action="store_true", help="List bounded ZIP central-directory metadata without extracting members")
    p.add_argument("--zip-max-members", type=int, default=1000, help="Maximum ZIP members listed per attachment")
    p.add_argument("--zip-max-total-members", type=int, default=10000, help="Maximum ZIP members listed for the entire execution")
    p.add_argument(
        "--extension",
        action="append",
        default=[],
        help="Optional filename-extension filter; repeat or provide comma-separated values (for example pdf,docx)",
    )
    _add_selector(p, require=False)
    _add_phish_hunt_report_selector(p)

    p = sub.add_parser("export-messages", help="Export EMLs, companion review TXT files, CSV, and manifest")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output", required=True, type=_path)
    _add_selector(p, require=False)

    p = sub.add_parser("scope", help="Manage named logical selections")
    scope_sub = p.add_subparsers(dest="scope_command", required=True)
    c = scope_sub.add_parser("create")
    c.add_argument("--case", required=True, type=_path)
    c.add_argument("--name", required=True)
    c.add_argument("--start", required=True)
    c.add_argument("--end", required=True)
    l = scope_sub.add_parser("list")
    l.add_argument("--case", required=True, type=_path)

    p = sub.add_parser("phish-hunt-preset", help="Print or export a bundled starter Phish Hunt config.json")
    p.add_argument("--name", required=True, choices=[item["name"] for item in available_presets()])
    p.add_argument("--output", type=_path, help="Optional destination config.json; prints the document when omitted")

    p = sub.add_parser("phish-hunt", help="Score a mandatory date range or named scope using a saved factor configuration")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output-root", type=_path, help="Root folder; every execution creates a new run subfolder")
    p.add_argument("--config", type=_path, help="JSON scoring configuration; defaults to the bundled general phishing configuration")
    p.add_argument("--run-name", help="Human-readable run name used in the unique report folder")
    p.add_argument("--scope", help="Existing named scope")
    p.add_argument("--start", help="Start time, inclusive, ISO 8601 with offset/Z")
    p.add_argument("--end", help="End time, exclusive, ISO 8601 with offset/Z")
    p.add_argument("--large-case", action="store_true", help="Stream hunt outputs and write JSON Lines")

    p = sub.add_parser("phish-hunt-list", help="List prior Phish Hunt executions recorded in the case")
    p.add_argument("--case", required=True, type=_path)

    p = sub.add_parser("string-search", help="Search local case data for a case-insensitive literal string")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--query", required=True, help="Literal case-insensitive string; no regular expressions or fuzzy matching")
    p.add_argument("--database", action="store_true", help="Search every SQLite field")
    p.add_argument("--exported-text-dir", type=_path, help="Search exported message review TXT files under this folder")
    p.add_argument("--reports", action="store_true", help="Search text-based files under the case reports folder")
    p.add_argument("--start", help="Optional SQLite-only start time, inclusive")
    p.add_argument("--end", help="Optional SQLite-only end time, exclusive")
    p.add_argument("--output-root", type=_path, help="Output root; defaults to /case/reports/string_search")

    p = sub.add_parser("qr", help="Decode QR codes offline from stored image and PDF attachments")
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--output-root", type=_path, help="Output root; defaults to /case/reports/qr")
    p.add_argument("--max-pdf-pages", type=int, default=100, help="Maximum rendered pages per PDF attachment")
    p.add_argument("--render-dpi", type=int, default=144, help="PDF render DPI, 72-600")
    _add_selector(p, require=False)
    _add_phish_hunt_report_selector(p)

    p = sub.add_parser(
        "evaluate-phishing-email",
        help="Evaluate one case message or standalone EML/MSG against the Phish Hunt factor catalog",
    )
    p.add_argument("--case", required=True, type=_path)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--sha256", dest="evaluate_sha256", help="Existing case message SHA-256")
    source.add_argument("--email-file", type=_path, help="New EML or MSG file mounted read-only")
    p.add_argument(
        "--allow-case-history",
        action="store_true",
        help="For a new file not already in the case, evaluate case-history factors against the selected case anyway",
    )
    p.add_argument("--output-root", type=_path, help="Output root; defaults to /case/reports/evaluate_phishing_email")

    p = sub.add_parser("run", help="Ingest and produce core reports in one pipeline")
    p.add_argument("--input", required=True, type=_path)
    p.add_argument("--case", required=True, type=_path)
    p.add_argument("--start")
    p.add_argument("--end")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--include-deleted", action="store_true", help="Pass readpst -D to include recoverable deleted PST items")
    p.add_argument("--allow-low-disk", action="store_true", help="Override PST disk-space preflight warning")
    p.add_argument("--disk-multiplier", type=float, default=5.0, help="Estimated case-space multiplier for PST preflight")
    p.add_argument("--large-case", action="store_true", help="Stream reports and use JSON Lines for large cases")
    p.add_argument(
        "--organization-domain",
        action="append",
        default=None,
        help="Analyst-declared organization domain for direction and lookalike context; repeat for multiple domains",
    )

    p = sub.add_parser("case-context", help="Recompute and show PST-derived trusted mail context without prompting for server IDs")
    p.add_argument("--case", required=True, type=_path)

    p = sub.add_parser("case-config", help="Set analyst-known case context that is not trusted-server inference")
    p.add_argument("--case", required=True, type=_path)
    domain_group = p.add_mutually_exclusive_group(required=True)
    domain_group.add_argument(
        "--organization-domain",
        action="append",
        help="Replace organization domains; repeat for multiple domains or use comma-separated values",
    )
    domain_group.add_argument(
        "--clear-organization-domains",
        action="store_true",
        help="Clear analyst-declared organization domains; PST inference may repopulate them",
    )

    p = sub.add_parser("doctor", help="Report runtime dependencies and case readiness")
    p.add_argument("--case", type=_path)
    return parser


def main(argv: list[str] | None = None) -> int:
    install_runtime_guardrails()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.quiet:
        print(f"{PROJECT_NAME} {__version__}", file=sys.stderr)
        print(MOTTO, file=sys.stderr)
    progress = (lambda _message: None) if args.quiet else console_progress
    try:
        if args.command == "ingest":
            progress(
                "[INGEST] Input discovery, PST extraction, and message indexing starting. "
                "This can take a LONG time for larger PST files."
            )
            stats = ingest_path(
                args.input,
                args.case,
                recursive=not args.no_recursive,
                workers=args.workers,
                include_deleted=args.include_deleted,
                organization_domains=args.organization_domain,
                allow_low_disk=args.allow_low_disk,
                disk_multiplier=args.disk_multiplier,
                progress=progress,
            )
            print(json.dumps(stats, indent=2))
            return 2 if stats["errors"] else 0
        if args.command == "doctor":
            print(json.dumps(run_doctor(args.case), indent=2))
            return 0
        if args.command == "phish-hunt-preset":
            document = preset_config(args.name)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                temp = args.output.with_suffix(args.output.suffix + ".tmp")
                temp.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                temp.replace(args.output)
                print(json.dumps({"preset": args.name, "output": str(args.output), "enabled_factors": sum(1 for item in document["factors"] if item["enabled"])}, indent=2))
            else:
                print(json.dumps(document, indent=2, ensure_ascii=False))
            return 0
        if args.command == "run":
            progress(
                "[PIPELINE] Extraction to EML and indexing of messages, URLs, and attachments starting. "
                "This can take a LONG time for larger PST files."
            )
            stats = ingest_path(
                args.input,
                args.case,
                workers=args.workers,
                include_deleted=args.include_deleted,
                organization_domains=args.organization_domain,
                allow_low_disk=args.allow_low_disk,
                disk_multiplier=args.disk_multiplier,
                progress=progress,
            )
            conn = connect_db(args.case)
            try:
                if args.start or args.end:
                    ids = resolve_message_hashes(conn, start=args.start, end=args.end)
                else:
                    ids = [r["message_sha256"] for r in conn.execute("SELECT message_sha256 FROM messages")]
                progress(f"[PIPELINE] URL indexing starting for {len(ids):,} selected message(s).")
                extract_urls(conn, args.case, ids, progress=progress)
                progress("[PIPELINE] Report generation starting.")
                output_base = args.case / "reports" / "pipeline"
                stage = staging_directory(output_base)
                try:
                    write_reports(conn, stage, ids, large_case=args.large_case)
                    write_url_report(conn, stage / "urls.csv", ids)
                    stamp = completion_timestamp()
                    final_output = finalize_directory(stage, output_base, stamp)
                    stage = None
                finally:
                    cleanup_staging(stage)
                progress(f"[PIPELINE] Full pipeline complete: output={final_output}")
            finally:
                conn.close()
            print(json.dumps({
                "ingest": stats,
                "selected": len(ids),
                "completion_timestamp": stamp,
                "output": str(final_output),
            }, indent=2))
            return 2 if stats["errors"] else 0

        load_case(args.case)
        conn = connect_db(args.case)
        initialize_schema(conn)
        try:
            if args.command == "case-config":
                domains = [] if args.clear_organization_domains else (args.organization_domain or [])
                normalized_domains = set_organization_domains(args.case, domains)
                inferred = recompute_case_context(conn, args.case)
                print(json.dumps({
                    "case": str(args.case),
                    "organization_domains": normalized_domains,
                    "organization_domains_source": inferred.get("organization_domains_source"),
                    "message_direction_recomputed": True,
                    "trusted_server_configuration_changed": False,
                }, indent=2))
                return 0
            if args.command == "case-context":
                inferred = recompute_case_context(conn, args.case)
                auth_available = bool(inferred.get("trusted_authserv_ids"))
                received_available = bool(inferred.get("trusted_received_hosts") or inferred.get("trusted_received_domains"))
                print(json.dumps({
                    "case": str(args.case),
                    "inferred_context": inferred,
                    "dependent_factor_availability": {
                        "trusted_authentication": {
                            "available": auth_available,
                            "factor_ids": sorted(AUTH_FACTOR_IDS),
                            "behavior_when_unavailable": "removed from the effective Phish Hunt configuration",
                        },
                        "trusted_received_boundary": {
                            "available": received_available,
                            "factor_ids": sorted(RECEIVED_FACTOR_IDS),
                            "behavior_when_unavailable": "removed from the effective Phish Hunt configuration",
                        },
                    },
                }, indent=2))
                return 0
            if args.command == "phish-hunt":
                date_requested = bool(args.start or args.end)
                selectors = int(bool(args.scope)) + int(date_requested)
                if selectors != 1:
                    raise ValueError("Phish Hunt requires exactly one selection: --scope or --start/--end")
                if date_requested and (not args.start or not args.end):
                    raise ValueError("Phish Hunt date selection requires both --start and --end")
                ids = resolve_message_hashes(
                    conn,
                    scope=args.scope,
                    start=args.start,
                    end=args.end,
                )
                span = selection_span_days(conn, start=args.start, end=args.end, scope=args.scope)
                if span is not None and span > 7:
                    progress(
                        f"[PHISH_HUNT] WARNING: the selected window spans {span:.1f} days and may take a long time."
                    )
                progress(
                    f"[PHISH_HUNT] Scoring starting for {len(ids):,} message(s). The higher the output CSV score, the more likely the message matches the configured phishing indicators."
                )
                config = load_scoring_config(args.config)
                output_root = args.output_root or (args.case / "reports" / "phish_hunt")
                result = run_phish_hunt(
                    conn,
                    args.case,
                    ids,
                    config=config,
                    output_root=output_root,
                    run_name=args.run_name,
                    start=args.start,
                    end=args.end,
                    scope=args.scope,
                    progress=progress,
                    large_case=args.large_case,
                )
                print(json.dumps(result, indent=2))
                return 0
            if args.command == "phish-hunt-list":
                print(json.dumps(list_hunt_runs(conn), indent=2))
                return 0

            if args.command == "string-search":
                progress("[STRING_SEARCH] Local literal string search starting.")
                output_root = args.output_root or (args.case / "reports" / "string_search")
                result = run_string_search(
                    conn,
                    args.case,
                    query=args.query,
                    search_database=args.database,
                    exported_text_dir=args.exported_text_dir,
                    search_reports=args.reports,
                    start=args.start,
                    end=args.end,
                    output_root=output_root,
                )
                progress(f"[STRING_SEARCH] Search complete: {result['matches']:,} match(es); output={result['run_directory']}")
                print(json.dumps(result, indent=2))
                return 0
            if args.command == "evaluate-phishing-email":
                progress("[EVALUATE_EMAIL] Evaluating the selected email against the Phish Hunt factor catalog.")
                output_root = args.output_root or (args.case / "reports" / "evaluate_phishing_email")
                result = evaluate_phishing_email(
                    conn,
                    args.case,
                    message_sha256=args.evaluate_sha256,
                    email_path=args.email_file,
                    allow_case_history_override=args.allow_case_history,
                    output_root=output_root,
                )
                progress(f"[EVALUATE_EMAIL] Evaluation complete: output={result['run_directory']}")
                print(json.dumps(result, indent=2))
                return 0

            if args.command == "qr":
                progress("[QR] Offline QR evaluation starting. Decoded URLs will not be contacted.")
                ids = _resolved_for_analysis(args, conn, args.case, require=False)
                output_root = args.output_root or (args.case / "reports" / "qr")
                result = evaluate_qrs(
                    conn, args.case, ids, output_root=output_root,
                    max_pdf_pages=args.max_pdf_pages, render_dpi=args.render_dpi, progress=progress,
                )
                progress(f"[QR] Evaluation complete: {result['qr_results']:,} result(s); output={result['run_directory']}")
                print(json.dumps(result, indent=2))
                return 0

            if args.command == "report":
                progress("[REPORT] Report generation starting.")
                require = any((args.one_sha256, args.sha256_csv, args.scope, args.all_messages, args.start, args.end))
                ids = _resolved(args, conn, require=require) if require else None
                output = args.output or (args.case / "reports" / "core")
                paths = write_timestamped_reports(conn, output, ids, large_case=args.large_case)
                progress(f"[REPORT] Report generation complete: output={paths['output_directory']}")
                print(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))
                return 0
            if args.command == "urls":
                progress("[URLS] Offline URL-string indexing and report generation starting.")
                ids = _resolved_for_analysis(args, conn, args.case, require=False)
                inserted = extract_urls(conn, args.case, ids, progress=progress)
                output = args.output or (args.case / "reports" / "urls.csv")
                report_result = write_timestamped_url_report(conn, output, ids)
                progress(f"[URLS] Report complete: output={report_result['output']}")
                print(json.dumps({"selected": len(ids), "new_urls": inserted, **report_result}, indent=2))
                return 0
            if args.command == "attachments":
                progress("[ATTACHMENTS] Attachment reporting and optional inert-byte copying starting.")
                ids = _resolved_for_analysis(args, conn, args.case, require=False)
                result = export_attachment_run(
                    conn,
                    args.output,
                    ids,
                    copy_files=args.copy_files,
                    files_output_base=args.copy_output,
                    extensions=args.extension,
                    list_zip_contents=args.list_zip_contents,
                    zip_max_members=args.zip_max_members,
                    zip_max_total_members=args.zip_max_total_members,
                )
                progress(f"[ATTACHMENTS] Attachment operation complete: output={result['report_directory']}")
                print(json.dumps(result, indent=2))
                return 0
            if args.command == "export-messages":
                progress("[EXPORT] Selected message export starting.")
                ids = _resolved(args, conn, require=True)
                manifest = export_messages(conn, args.output, ids)
                progress(
                    f"[EXPORT] Message export complete: {manifest['message_count']:,} message(s); "
                    f"output={manifest['output_directory']}"
                )
                print(json.dumps({
                    "message_count": manifest["message_count"],
                    "completion_timestamp": manifest["completion_timestamp"],
                    "output": manifest["output_directory"],
                }, indent=2))
                return 0 if ids else 3
            if args.command == "scope":
                if args.scope_command == "create":
                    count = create_scope(conn, name=args.name, start=args.start, end=args.end)
                    print(json.dumps({"scope": args.name, "message_count": count}, indent=2))
                    return 0
                rows = [dict(r) for r in conn.execute(
                    """SELECT s.name,s.criteria_json,s.created_utc,COUNT(sm.message_sha256) AS message_count
                       FROM scopes s LEFT JOIN scope_messages sm ON sm.scope_id=s.scope_id
                       GROUP BY s.scope_id ORDER BY s.name""")]
                for row in rows:
                    row["criteria"] = json.loads(row.pop("criteria_json"))
                print(json.dumps(rows, indent=2))
                return 0
        finally:
            conn.close()

        parser.error("Unknown command")
    except (ValueError, FileNotFoundError, RuntimeError, sqlite3.Error) as exc:
        print(f"threadsaw: error: {exc}", file=sys.stderr)
        return 2
    return 0
