from __future__ import annotations

import json
import os
import shutil
import tempfile
from subprocess import CompletedProcess
from pathlib import Path
from typing import Any
from email.utils import parseaddr

from .case import initialize_case, load_case
from .db import connect_db, initialize_schema, record_error
from .parsers.eml import ParsedMessage, parse_eml
from .parsers.msg import parse_msg
from .security import run_readpst
from .util import available_disk_bytes, estimate_pst_case_bytes, file_hashes, iter_files, relative_or_absolute, safe_filename, utc_now
from .progress import ProgressCallback, ProgressCounter, console_progress
from .domains import registrable_domain
from .case_context import recompute_case_context, set_organization_domains
import re

SUPPORTED_EXTENSIONS = {".pst", ".eml", ".msg"}


def _canonical_source_copy(case_dir: Path, path: Path, source_type: str, sha256: str) -> Path | None:
    """Copy loose EML/MSG bytes into the case without opening or transforming them."""
    if source_type not in {"EML", "MSG"}:
        return None
    suffix = ".eml" if source_type == "EML" else ".msg"
    target = case_dir / "sources" / source_type.lower() / f"{sha256}{suffix}"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        return target
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(fd)
    try:
        shutil.copyfile(path, temp_name)
        os.replace(temp_name, target)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return target


def _insert_source(conn, case_dir: Path, *, path: Path, source_type: str, parent_source_id: int | None,
                   parser_name: str, parser_version: str | None, status: str = "discovered",
                   error: str | None = None) -> int:
    sha256, md5, size = file_hashes(path)
    canonical_path = None
    if parent_source_id is None and source_type in {"EML", "MSG"}:
        canonical_path = _canonical_source_copy(case_dir, path, source_type, sha256)
    existing = conn.execute(
        "SELECT source_id,canonical_path FROM sources WHERE source_path=? AND sha256=?",
        (str(path.resolve()), sha256),
    ).fetchone()
    if existing:
        if canonical_path and not existing["canonical_path"]:
            conn.execute("UPDATE sources SET canonical_path=? WHERE source_id=?", (str(canonical_path.resolve()), existing["source_id"]))
            conn.commit()
        return int(existing["source_id"])
    cursor = conn.execute(
        """INSERT INTO sources(source_type,source_path,source_relative_path,canonical_path,sha256,md5,size_bytes,
           parent_source_id,parser_name,parser_version,status,error,added_utc)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source_type, str(path.resolve()), path.name, str(canonical_path.resolve()) if canonical_path else None,
         sha256, md5, size, parent_source_id, parser_name, parser_version, status, error, utc_now()),
    )
    conn.commit()
    return int(cursor.lastrowid)


def _artifact_path(case_dir: Path, sha256: str) -> Path:
    return case_dir / "artifacts" / "attachments" / sha256[:2] / sha256[2:4] / sha256


def _store_parsed(conn, case_dir: Path, source_id: int, parsed: ParsedMessage, *,
                  fmt: str, derivation_status: str, eml_path: Path, config: dict[str, Any], recursion_depth: int = 0) -> bool:
    exists = conn.execute("SELECT 1 FROM messages WHERE message_sha256=?", (parsed.message_sha256,)).fetchone()
    if not exists:
        normalized_from = parseaddr(parsed.from_address or "")[1].strip().lower() or None
        normalized_domain = registrable_domain(normalized_from.rsplit("@", 1)[1]) if normalized_from and "@" in normalized_from else None
        counted_attachments = [item for item in parsed.attachments if not item.is_inline]
        normalized_subject = re.sub(r"^\s*(?:(?:re|fw|fwd|aw|sv)\s*:\s*)+", "", parsed.subject or "", flags=re.I)
        normalized_subject = " ".join(normalized_subject.split()).casefold()
        conn.execute(
            """INSERT INTO messages(message_sha256,format,derivation_status,eml_path,internet_message_id,subject,normalized_subject,
               from_address,from_address_normalized,from_domain_registrable,direction,reply_to,return_path,header_date_raw,header_date_utc,top_received_utc,
               trusted_received_utc,selected_date_utc,selected_date_source,sender_ips_json,raw_headers_text,body_text,
               body_text_source,body_html,date_discrepancy_seconds,defects_json,attachment_count,has_attachments,indexed_utc)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (parsed.message_sha256, fmt, derivation_status, str(eml_path.resolve()), parsed.internet_message_id,
             parsed.subject, normalized_subject, parsed.from_address, normalized_from, normalized_domain, None, parsed.reply_to, parsed.return_path, parsed.header_date_raw,
             parsed.header_date_utc, parsed.top_received_utc, parsed.trusted_received_utc,
             parsed.selected_date_utc, parsed.selected_date_source, json.dumps(parsed.sender_ips),
             parsed.raw_headers_text, parsed.body_text, parsed.body_text_source, parsed.body_html,
             parsed.date_discrepancy_seconds, json.dumps(parsed.defects), len(counted_attachments),
             int(bool(counted_attachments)), utc_now()),
        )
        for item in parsed.recipients:
            conn.execute(
                "INSERT INTO recipients(message_sha256,recipient_type,display_name,email_address,domain) VALUES(?,?,?,?,?)",
                (parsed.message_sha256, item["recipient_type"], item["display_name"], item["email_address"], item["domain"]),
            )
        for hop in parsed.received_hops:
            conn.execute(
                """INSERT INTO received_hops(message_sha256,hop_order,raw_value,parsed_date_utc,sender_ips_json,trusted)
                   VALUES(?,?,?,?,?,?)""",
                (parsed.message_sha256, hop["hop_order"], hop["raw_value"], hop["parsed_date_utc"],
                 json.dumps(hop["sender_ips"]), int(hop["trusted"])),
            )
        for auth in parsed.auth_results:
            conn.execute(
                """INSERT INTO authentication_results(message_sha256,authserv_id,spf_result,dkim_result,dmarc_result,
                   arc_result,trusted,raw_value) VALUES(?,?,?,?,?,?,?,?)""",
                (parsed.message_sha256, auth["authserv_id"], auth["spf_result"], auth["dkim_result"],
                 auth["dmarc_result"], auth["arc_result"], int(auth["trusted"]), auth["raw_value"]),
            )
        for attachment in parsed.attachments:
            artifact = _artifact_path(case_dir, attachment.sha256)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            if not artifact.exists():
                artifact.write_bytes(attachment.data)
            conn.execute(
                """INSERT INTO attachments(message_sha256,part_index,original_filename,safe_filename,
                   content_type_declared,size_bytes,sha256,md5,artifact_path,content_disposition,content_id,
                   executable_format,is_inline,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (parsed.message_sha256, attachment.part_index, attachment.original_filename, attachment.safe_filename,
                 attachment.content_type, len(attachment.data), attachment.sha256, attachment.md5,
                 str(artifact.resolve()), attachment.content_disposition, attachment.content_id,
                 attachment.executable_format, int(attachment.is_inline), "stored"),
            )
    conn.execute("INSERT OR IGNORE INTO message_sources(message_sha256,source_id) VALUES(?,?)", (parsed.message_sha256, source_id))
    if recursion_depth < 10:
        for embedded in parsed.embedded_messages:
            if embedded.message_sha256 == parsed.message_sha256:
                continue
            embedded_path = case_dir / "artifacts" / "embedded-messages" / embedded.message_sha256[:2] / f"{embedded.message_sha256}.eml"
            embedded_path.parent.mkdir(parents=True, exist_ok=True)
            if not embedded_path.exists():
                embedded_path.write_bytes(embedded.raw_bytes)
            child = parse_eml(embedded.raw_bytes, config)
            _store_parsed(
                conn, case_dir, source_id, child, fmt="EML", derivation_status="attached-eml",
                eml_path=embedded_path, config=config, recursion_depth=recursion_depth + 1,
            )
            conn.execute(
                "INSERT OR IGNORE INTO message_relationships(parent_message_sha256,child_message_sha256,parent_part_index,relationship_type) VALUES(?,?,?,?)",
                (parsed.message_sha256, child.message_sha256, embedded.parent_part_index, "message/rfc822"),
            )
    conn.execute("UPDATE sources SET status='indexed' WHERE source_id=?", (source_id,))
    conn.commit()
    return not bool(exists)


def _source_canonical_path(conn, source_id: int, fallback: Path) -> Path:
    row = conn.execute("SELECT canonical_path FROM sources WHERE source_id=?", (source_id,)).fetchone()
    if row and row["canonical_path"]:
        return Path(row["canonical_path"])
    return fallback


def _ingest_eml(conn, case_dir: Path, path: Path, config: dict[str, Any], parent_source_id: int | None = None) -> bool:
    source_id = _insert_source(conn, case_dir, path=path, source_type="EML", parent_source_id=parent_source_id,
                               parser_name="python-email", parser_version=None)
    parse_path = path if parent_source_id is not None else _source_canonical_path(conn, source_id, path)
    raw = parse_path.read_bytes()
    parsed = parse_eml(raw, config)
    derivation = "pst-derived-eml" if parent_source_id else "original-eml"
    return _store_parsed(conn, case_dir, source_id, parsed, fmt="EML", derivation_status=derivation, eml_path=parse_path, config=config)


def _ingest_msg(conn, case_dir: Path, path: Path, config: dict[str, Any]) -> bool:
    source_id = _insert_source(conn, case_dir, path=path, source_type="MSG", parent_source_id=None,
                               parser_name="extract-msg", parser_version="0.55.0")
    parse_path = _source_canonical_path(conn, source_id, path)
    parsed, derived = parse_msg(parse_path, config)
    derived_dir = case_dir / "extracted" / "derived-msg"
    derived_dir.mkdir(parents=True, exist_ok=True)
    derived_path = derived_dir / f"{parsed.message_sha256}.eml"
    if not derived_path.exists():
        derived_path.write_bytes(derived)
    return _store_parsed(conn, case_dir, source_id, parsed, fmt="MSG", derivation_status="derived-eml-from-msg", eml_path=derived_path, config=config)


def _extract_pst(
    conn, case_dir: Path, pst_path: Path, config: dict[str, Any], workers: int,
    progress: ProgressCallback, include_deleted: bool = False, *, allow_low_disk: bool = False,
    disk_multiplier: float = 5.0,
) -> tuple[int, int, int]:
    pst_source_id = _insert_source(conn, case_dir, path=pst_path, source_type="PST", parent_source_id=None,
                                   parser_name="readpst", parser_version=None)
    pst_sha = conn.execute("SELECT sha256 FROM sources WHERE source_id=?", (pst_source_id,)).fetchone()["sha256"]
    free_bytes = available_disk_bytes(case_dir)
    estimated_bytes = estimate_pst_case_bytes(pst_path.stat().st_size, multiplier=disk_multiplier)
    progress(
        f"[PREFLIGHT] PST size={pst_path.stat().st_size:,} bytes; estimated case space={estimated_bytes:,}; "
        f"free case-filesystem space={free_bytes:,}."
    )
    if free_bytes < estimated_bytes:
        message = (
            f"Estimated free space is insufficient for this PST. Need approximately {estimated_bytes:,} bytes "
            f"but only {free_bytes:,} bytes are available. Use --allow-low-disk to proceed at your own risk."
        )
        if not allow_low_disk:
            raise RuntimeError(message)
        progress(f"[PREFLIGHT] WARNING: {message}")
    extraction_mode = "with-deleted" if include_deleted else "standard"
    target = case_dir / "extracted" / f"{safe_filename(pst_path.stem)}_{pst_sha[:12]}_{extraction_mode}"
    target.mkdir(parents=True, exist_ok=True)
    command = ["readpst", "-e", "-t", "e"] + (["-D"] if include_deleted else []) + ["-j", str(max(0, workers)), "-o", str(target), str(pst_path)]
    completion_marker = target / ".threadsaw-extraction-complete.json"
    existing_emls = list(target.rglob("*.eml"))
    try:
        version = run_readpst(["-V"], timeout=15)
        version_text = (version.stdout or version.stderr).strip() or None
        if existing_emls and completion_marker.exists():
            progress(f"[PST] Reusing verified extraction: {pst_path.name} ({len(existing_emls):,} EML files)")
            result = CompletedProcess(command, 0, stdout="Reused verified extraction output.\n", stderr="")
        else:
            if existing_emls:
                preserved = target.with_name(target.name + ".incomplete_" + utc_now().replace(":", "").replace("-", ""))
                progress(f"[PST] Preserving incomplete extraction before clean retry: {preserved}")
                target.rename(preserved)
                target.mkdir(parents=True, exist_ok=True)
            progress(f"[PST] Starting readpst: {pst_path.name}")
            result = run_readpst(command[1:], timeout=None)
    except FileNotFoundError as exc:
        conn.execute("UPDATE sources SET status='failed',error=? WHERE source_id=?", (str(exc), pst_source_id))
        conn.commit()
        raise RuntimeError("readpst was not found. Use the Docker image or install libpst/readpst.") from exc
    conn.execute("UPDATE sources SET parser_version=?, status=?, error=? WHERE source_id=?",
                 (version_text, "extracted" if result.returncode == 0 else "failed",
                  None if result.returncode == 0 else (result.stderr or result.stdout), pst_source_id))
    conn.commit()
    log_path = case_dir / "logs" / f"readpst_{pst_sha[:12]}.log"
    log_path.write_text("COMMAND: " + " ".join(command) + "\n\nSTDOUT:\n" + result.stdout + "\nSTDERR:\n" + result.stderr,
                        encoding="utf-8")
    eml_paths = sorted(target.rglob("*.eml"))
    extraction_complete = result.returncode == 0
    marker_payload = {
        "pst_sha256": pst_sha, "include_deleted": include_deleted, "eml_count": len(eml_paths),
        "completed_utc": utc_now(), "status": "complete" if extraction_complete else "partial",
        "readpst_returncode": result.returncode,
    }
    marker_name = ".threadsaw-extraction-complete.json" if extraction_complete else ".threadsaw-extraction-partial.json"
    (target / marker_name).write_text(json.dumps(marker_payload, indent=2), encoding="utf-8")
    if extraction_complete:
        progress(f"[PST] Extraction complete: {len(eml_paths):,} EML files")
    else:
        progress(f"[PST] WARNING: readpst failed; indexing {len(eml_paths):,} partial EML file(s) before stopping. See {log_path}")
    indexed = 0
    parse_errors = 0
    counter = ProgressCounter("INDEX", len(eml_paths), progress, every=100)
    for discovered, eml_path in enumerate(eml_paths, start=1):
        try:
            if _ingest_eml(conn, case_dir, eml_path, config, parent_source_id=pst_source_id):
                indexed += 1
        except Exception as exc:
            parse_errors += 1
            record_error(conn, source_path=str(eml_path.resolve()), message_sha256=None, stage="pst-eml-ingest",
                         error_type=type(exc).__name__, error_detail=str(exc), recorded_utc=utc_now())
            progress(f"[INDEX] ERROR: {eml_path.name}: {type(exc).__name__}: {exc}")
        counter.update(discovered, detail=eml_path.name)
    if not extraction_complete:
        raise RuntimeError(
            f"readpst failed for {pst_path}; {indexed:,} partial message(s) were indexed and {parse_errors:,} failed. See {log_path}"
        )
    return len(eml_paths), indexed, parse_errors


def ingest_path(
    input_path: Path,
    case_dir: Path,
    *,
    recursive: bool = True,
    workers: int = 4,
    include_deleted: bool = False,
    organization_domains: list[str] | None = None,
    allow_low_disk: bool = False,
    disk_multiplier: float = 5.0,
    progress: ProgressCallback = console_progress,
) -> dict[str, int]:
    initialize_case(case_dir)
    if organization_domains is not None:
        set_organization_domains(case_dir, organization_domains)
    case_data = load_case(case_dir)
    config = case_data.get("config", {})
    conn = connect_db(case_dir)
    initialize_schema(conn)
    stats = {"discovered": 0, "indexed_new": 0, "duplicates": 0, "errors": 0, "pst_extracted_emls": 0}
    try:
        candidates = [p for p in iter_files(input_path, recursive=recursive) if p.suffix.lower() in SUPPORTED_EXTENSIONS]
        progress(f"[DISCOVER] Found {len(candidates):,} supported input file(s)")
        source_counter = ProgressCounter("SOURCE", len(candidates), progress, every=1)
        for source_index, path in enumerate(candidates, start=1):
            source_counter.update(source_index, detail=path.name)
            stats["discovered"] += 1
            try:
                suffix = path.suffix.lower()
                if suffix == ".eml":
                    created = _ingest_eml(conn, case_dir, path, config)
                    stats["indexed_new" if created else "duplicates"] += 1
                elif suffix == ".msg":
                    created = _ingest_msg(conn, case_dir, path, config)
                    stats["indexed_new" if created else "duplicates"] += 1
                elif suffix == ".pst":
                    extracted, created, parse_errors = _extract_pst(
                        conn, case_dir, path, config, workers, progress, include_deleted=include_deleted,
                        allow_low_disk=allow_low_disk, disk_multiplier=disk_multiplier,
                    )
                    stats["pst_extracted_emls"] += extracted
                    stats["indexed_new"] += created
                    stats["duplicates"] += max(0, extracted - created - parse_errors)
                    stats["errors"] += parse_errors
            except Exception as exc:
                stats["errors"] += 1
                record_error(conn, source_path=str(path.resolve()), message_sha256=None, stage="ingest",
                             error_type=type(exc).__name__, error_detail=str(exc), recorded_utc=utc_now())
        inferred = recompute_case_context(conn, case_dir)
        stats["trusted_authserv_ids_inferred"] = len(inferred.get("trusted_authserv_ids", []))
        stats["trusted_received_hosts_inferred"] = len(inferred.get("trusted_received_hosts", []))
        progress(f"[OUTCOME] discovered={stats['discovered']:,} indexed_new={stats['indexed_new']:,} duplicates={stats['duplicates']:,} errors={stats['errors']:,} pst_emls={stats['pst_extracted_emls']:,}")
        return stats
    finally:
        conn.close()
