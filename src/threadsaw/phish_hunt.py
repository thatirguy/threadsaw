from __future__ import annotations

import csv
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .case import load_case
from .case_context import recompute_case_context, filter_config_for_available_context
from .factor_catalog import FACTOR_BY_ID, FACTOR_CATALOG, LEGACY_FACTORS
from .factor_evaluators import EVALUATORS, PENDING_REASONS
from .phish_hunt_presets import preset_config
from .message_context import recipient_fields
from .progress import ProgressCallback, ProgressCounter, console_progress
from .reports import MESSAGE_FIELDS, message_rows
from .output_naming import cleanup_staging, completion_timestamp, finalize_directory, staging_directory
from .util import atomic_write_csv, atomic_write_json, chunked, human_folder_name, parse_iso8601, utc_now
from .urls import extract_urls
from .archive_inspection import inspect_zip_attachments

CONFIG_VERSION = 1
EFFECT_MODES = {
    "risk_when_yes": "Yes +weight / No 0",
    "trust_when_yes": "Yes -weight / No 0",
    "bidirectional_risk": "Yes +weight / No -weight",
    "bidirectional_trust": "Yes -weight / No +weight",
}


@dataclass(frozen=True)
class FactorDefinition:
    factor_id: str
    label: str
    category: str
    subcategory: str
    description: str
    load: str
    implemented: bool
    requires_case_history: bool
    evaluator_version: str
    evaluator: Callable[[Any, Any, dict[str, Any]], dict[str, Any]]


def _evaluate_cross_domain_message(conn, message: Any, _factor_config: dict[str, Any]) -> dict[str, Any]:
    from .factor_evaluators import _address_domain, _recipient_domains

    sender_domain = _address_domain(message["from_address"])
    recipient_domains = _recipient_domains(conn, message["message_sha256"])
    if not sender_domain:
        return {"answer": "UNKNOWN", "status": "unknown", "evidence": "", "source": "messages.from_address", "reason": "A usable sender domain was not available."}
    if not recipient_domains:
        return {"answer": "UNKNOWN", "status": "unknown", "evidence": f"sender_domain={sender_domain}", "source": "messages.from_address and recipients", "reason": "No usable recipient domain was available."}
    different = [domain for domain in recipient_domains if domain != sender_domain]
    return {
        "answer": "YES" if different else "NO",
        "status": "evaluated",
        "evidence": f"sender_domain={sender_domain}; recipient_domains={';'.join(recipient_domains)}",
        "source": "messages.from_address and recipients",
        "reason": "At least one recipient domain differs from the sender domain." if different else "All recorded recipient domains match the sender domain.",
    }


def _evaluate_pending(_conn, _message: Any, factor_config: dict[str, Any]) -> dict[str, Any]:
    factor_id = str(factor_config.get("factor_id") or "")
    reason = PENDING_REASONS.get(
        factor_id,
        "The evaluator is not yet implemented or a required ingestion field is unavailable.",
    )
    return {
        "answer": "UNKNOWN",
        "status": "unavailable",
        "evidence": "",
        "source": "factor catalog and SQLite prerequisites",
        "reason": reason + " It contributes zero points and is recorded as UNKNOWN.",
    }


def _definition(metadata: dict[str, Any]) -> FactorDefinition:
    factor_id = metadata["factor_id"]
    evaluator = EVALUATORS.get(factor_id)
    if factor_id == "cross_domain_message":
        evaluator = _evaluate_cross_domain_message
    if evaluator is None:
        evaluator = _evaluate_pending
    return FactorDefinition(
        factor_id=factor_id,
        label=metadata["label"],
        category=metadata["top_category"],
        subcategory=metadata["subcategory"],
        description=metadata["description"],
        load=metadata["load"],
        implemented=bool(metadata.get("implemented")),
        requires_case_history=bool(metadata.get("requires_case_history")),
        evaluator_version=metadata.get("evaluator_version", "catalog-1"),
        evaluator=evaluator,
    )


FACTOR_REGISTRY: dict[str, FactorDefinition] = {
    item["factor_id"]: _definition(item) for item in [*FACTOR_CATALOG, *LEGACY_FACTORS]
}


def prototype_default_config() -> dict[str, Any]:
    """Return the General phishing starter preset.

    The old single-factor demonstration remains accepted through the hidden
    legacy registry, but new CLI and GUI runs start from a complete, reviewable
    preset rather than a prototype-only factor.
    """
    return preset_config("general")


def all_factor_config(name: str = "Evaluate all factors", *, weight: int = 1) -> dict[str, Any]:
    """Return a normalized-ready configuration enabling every visible factor.

    The weight is intentionally uniform because this configuration is used to
    discover factor hits, not to claim a calibrated risk model.
    """
    if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
        raise ValueError("Evaluation weight must be a non-negative integer")
    return {
        "config_version": CONFIG_VERSION,
        "name": name,
        "preset": "evaluate-all-factors",
        "factors": [
            {
                "factor_id": item["factor_id"],
                "enabled": True,
                "weight": weight,
                "effect_mode": "risk_when_yes",
                "parameters": {p["name"]: p.get("default", "") for p in item.get("parameters", [])},
            }
            for item in FACTOR_CATALOG
        ],
    }


def empty_preset_config(name: str = "Clear") -> dict[str, Any]:
    return preset_config("clear") | {"name": name, "preset": "clear"}


FACTOR_ID_ALIASES = {
    # 0.6.0 documented this pending factor. Threadsaw 1.2 can finally evaluate
    # ZIP-family encryption flags from the bounded central-directory inventory.
    "encrypted_archive": "attachment_encrypted_zip",
}


def normalize_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    source = raw or prototype_default_config()
    if not isinstance(source, dict):
        raise ValueError("Phish Hunt configuration must be a JSON object")
    version = source.get("config_version", CONFIG_VERSION)
    if version != CONFIG_VERSION:
        raise ValueError(f"Unsupported Phish Hunt config_version {version!r}; expected {CONFIG_VERSION}")
    name = str(source.get("name") or "Custom").strip() or "Custom"
    preset = str(source.get("preset") or "custom").strip() or "custom"
    supplied = source.get("factors", [])
    if not isinstance(supplied, list):
        raise ValueError("Phish Hunt factors must be a list")

    by_id: dict[str, dict[str, Any]] = {}
    for item in supplied:
        if not isinstance(item, dict):
            raise ValueError("Each Phish Hunt factor configuration must be an object")
        factor_id = str(item.get("factor_id") or "").strip()
        factor_id = FACTOR_ID_ALIASES.get(factor_id, factor_id)
        if factor_id not in FACTOR_REGISTRY:
            raise ValueError(f"Unknown Phish Hunt factor: {factor_id or '[blank]'}")
        if factor_id in by_id:
            raise ValueError(f"Duplicate Phish Hunt factor: {factor_id}")
        enabled = item.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError(f"Factor {factor_id} enabled must be true or false")
        weight = item.get("weight", 0)
        if isinstance(weight, bool) or not isinstance(weight, int):
            raise ValueError(f"Factor {factor_id} weight must be an integer")
        if weight < 0:
            raise ValueError(f"Factor {factor_id} weight must be zero or greater; direction is set by effect_mode")
        effect_mode = str(item.get("effect_mode") or "risk_when_yes")
        if effect_mode not in EFFECT_MODES:
            raise ValueError(f"Factor {factor_id} has unsupported effect_mode {effect_mode!r}")
        parameters = item.get("parameters", {})
        if parameters is None:
            parameters = {}
        if not isinstance(parameters, dict):
            raise ValueError(f"Factor {factor_id} parameters must be an object")
        by_id[factor_id] = {
            "factor_id": factor_id,
            "enabled": enabled,
            "weight": weight,
            "effect_mode": effect_mode,
            "parameters": parameters,
        }

    normalized_factors: list[dict[str, Any]] = []
    ordered_ids = [item["factor_id"] for item in FACTOR_CATALOG]
    # Preserve a supplied legacy factor for compatibility without adding it to
    # every new configuration.
    ordered_ids.extend(fid for fid in by_id if fid not in ordered_ids)
    for factor_id in ordered_ids:
        definition = FACTOR_REGISTRY[factor_id]
        metadata = FACTOR_BY_ID[factor_id]
        defaults = {p["name"]: p.get("default", "") for p in metadata.get("parameters", [])}
        item = by_id.get(factor_id, {"factor_id": factor_id, "enabled": False, "weight": 0, "effect_mode": "risk_when_yes", "parameters": defaults})
        merged_parameters = {**defaults, **item.get("parameters", {})}
        normalized_factors.append({
            **item,
            "parameters": merged_parameters,
            "label": definition.label,
            "category": definition.category,
            "subcategory": definition.subcategory,
            "description": definition.description,
            "load": definition.load,
            "implemented": definition.implemented,
            "evaluator_version": definition.evaluator_version,
            "effect_description": EFFECT_MODES[item["effect_mode"]],
        })
    return {"config_version": CONFIG_VERSION, "name": name, "preset": preset, "factors": normalized_factors}


def load_scoring_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return normalize_config(prototype_default_config())
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return normalize_config(raw)


def config_hash(config: dict[str, Any]) -> str:
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _points_for(answer: str, weight: int, effect_mode: str) -> int:
    if answer not in {"YES", "NO"}:
        return 0
    if effect_mode == "risk_when_yes":
        return weight if answer == "YES" else 0
    if effect_mode == "trust_when_yes":
        return -weight if answer == "YES" else 0
    if effect_mode == "bidirectional_risk":
        return weight if answer == "YES" else -weight
    if effect_mode == "bidirectional_trust":
        return -weight if answer == "YES" else weight
    raise ValueError(f"Unsupported effect mode: {effect_mode}")


def evaluate_message(
    conn,
    message: Any,
    config: dict[str, Any],
    *,
    allow_case_history: bool = True,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    total = 0
    positive = 0
    negative = 0
    evaluated = 0
    unknown = 0
    max_possible_evaluated = 0
    unknown_positive_points = 0
    details: list[dict[str, Any]] = []
    reasons: list[tuple[int, str]] = []

    for factor_config in config["factors"]:
        if not factor_config["enabled"]:
            continue
        definition = FACTOR_REGISTRY[factor_config["factor_id"]]
        try:
            if definition.requires_case_history and not allow_case_history:
                result = {
                    "answer": "NOT_APPLICABLE",
                    "status": "standalone-skip",
                    "evidence": "",
                    "source": "evaluation context",
                    "reason": "This factor requires historical or cross-message case context and was not run for a standalone email.",
                }
            else:
                result = definition.evaluator(conn, message, factor_config)
            answer = str(result.get("answer") or "UNKNOWN").upper()
            status = str(result.get("status") or "evaluated")
            if answer not in {"YES", "NO", "UNKNOWN", "NOT_APPLICABLE", "ERROR"}:
                answer = "ERROR"
                status = "error"
                result["reason"] = "Evaluator returned an unsupported answer."
        except Exception as exc:  # Factor boundary: preserve the hunt and explain the failure.
            result = {
                "answer": "ERROR",
                "status": "error",
                "evidence": "",
                "source": "factor evaluator",
                "reason": f"Evaluator error: {type(exc).__name__}: {exc}",
            }
            answer = "ERROR"
            status = "error"

        points = _points_for(answer, factor_config["weight"], factor_config["effect_mode"])
        total += points
        positive += max(points, 0)
        negative += min(points, 0)
        positive_ceiling = factor_config["weight"] if factor_config["effect_mode"] in {"risk_when_yes", "bidirectional_risk", "bidirectional_trust"} else 0
        if answer in {"YES", "NO"}:
            evaluated += 1
            max_possible_evaluated += positive_ceiling
        else:
            unknown += 1
            unknown_positive_points += positive_ceiling
        if points:
            reasons.append((abs(points), f"{definition.label} ({points:+d})"))
        details.append(
            {
                "message_sha256": message["message_sha256"],
                "factor_id": definition.factor_id,
                "factor_label": definition.label,
                "answer": answer,
                "points": points,
                "weight": factor_config["weight"],
                "effect_mode": factor_config["effect_mode"],
                "evidence": result.get("evidence", ""),
                "source": result.get("source", ""),
                "status": status,
                "reason": result.get("reason", ""),
                "evaluator_version": definition.evaluator_version,
            }
        )

    reasons.sort(key=lambda item: item[0], reverse=True)
    summary = {
        "message_sha256": message["message_sha256"],
        "score": total,
        "positive_points": positive,
        "negative_points": negative,
        "evaluated_factor_count": evaluated,
        "unknown_factor_count": unknown,
        "max_possible_points_evaluated": max_possible_evaluated,
        "unknown_positive_points": unknown_positive_points,
        "positive_score_percent_evaluated": round((positive / max_possible_evaluated) * 100, 2) if max_possible_evaluated else None,
        "top_score_reasons": "; ".join(text for _magnitude, text in reasons[:5]),
    }
    return summary, details


PHISH_HUNT_PREFIX_FIELDS = [
    "selected_date_utc",
    "score",
    "from_address",
    "recipient_addresses",
    "subject",
    "message_sha256",
]
PHISH_HUNT_RUN_FIELDS = [
    "positive_points",
    "negative_points",
    "evaluated_factor_count",
    "unknown_factor_count",
    "max_possible_points_evaluated",
    "unknown_positive_points",
    "positive_score_percent_evaluated",
    "top_score_reasons",
    "phish_hunt_run_id",
    "config_name",
    "config_hash",
    "case_id",
]
PHISH_HUNT_FIELDS = PHISH_HUNT_PREFIX_FIELDS + [
    field for field in MESSAGE_FIELDS if field not in PHISH_HUNT_PREFIX_FIELDS
] + PHISH_HUNT_RUN_FIELDS
PHISH_HUNT_DETAIL_FIELDS = [
    "phish_hunt_run_id",
    "case_id",
    "message_sha256",
    "factor_id",
    "factor_label",
    "answer",
    "points",
    "weight",
    "effect_mode",
    "evidence",
    "source",
    "status",
    "reason",
    "evaluator_version",
]


def _run_base(output_root: Path, run_name: str, run_id: str) -> Path:
    readable = human_folder_name(run_name, "phish-hunt", max_length=48).replace(" ", "_")
    return output_root / f"{readable}_{run_id.rsplit('_', 1)[-1]}"


def _selection_json(*, start: str | None, end: str | None, scope: str | None) -> dict[str, Any]:
    if scope:
        return {"type": "named-scope", "scope": scope}
    return {
        "type": "date-range",
        "start": start,
        "end": end,
        "semantics": "start-inclusive/end-exclusive",
    }


def selection_span_days(conn, *, start: str | None = None, end: str | None = None, scope: str | None = None) -> float | None:
    if start or end:
        if not start or not end:
            raise ValueError("Phish Hunt date selection requires both --start and --end")
        return (parse_iso8601(end) - parse_iso8601(start)).total_seconds() / 86400
    if scope:
        row = conn.execute("SELECT criteria_json FROM scopes WHERE name=?", (scope,)).fetchone()
        if not row:
            raise ValueError(f"Named scope not found: {scope}")
        try:
            criteria = json.loads(row["criteria_json"])
            if criteria.get("type") == "date-range" and criteria.get("start") and criteria.get("end"):
                return (parse_iso8601(criteria["end"]) - parse_iso8601(criteria["start"])).total_seconds() / 86400
        except (ValueError, TypeError, json.JSONDecodeError):
            return None
    return None


def run_phish_hunt(
    conn,
    case_dir: Path,
    ids: list[str],
    *,
    config: dict[str, Any],
    output_root: Path,
    run_name: str | None,
    start: str | None = None,
    end: str | None = None,
    scope: str | None = None,
    progress: ProgressCallback = console_progress,
    large_case: bool = False,
) -> dict[str, Any]:
    case_data = load_case(case_dir)
    case_id = str(case_data["case_id"])
    inferred_context = recompute_case_context(conn, case_dir)
    requested_config = normalize_config(config)
    normalized, context_removed_factors = filter_config_for_available_context(requested_config, inferred_context)
    unindexed_ids: list[str] = []
    for batch in chunked(ids):
        placeholders = ",".join("?" for _ in batch)
        unindexed_ids.extend(row["message_sha256"] for row in conn.execute(
            f"SELECT message_sha256 FROM messages WHERE message_sha256 IN ({placeholders}) AND url_indexed=0",
            batch,
        ).fetchall())
    if unindexed_ids:
        progress(f"[PHISH_HUNT] URL indexing was incomplete for {len(unindexed_ids):,} selected message(s); running deterministic offline URL indexing before scoring.")
        extract_urls(conn, case_dir, unindexed_ids, progress=progress)
    archive_inventory: dict[str, Any] | None = None
    archive_dependent_ids = {"attachment_executable_or_script", "attachment_encrypted_zip"}
    if any(
        item.get("enabled") and item.get("factor_id") in archive_dependent_ids
        for item in normalized.get("factors", [])
    ):
        progress(
            "[PHISH_HUNT] Running bounded ZIP-family central-directory inventory for enabled archive-dependent factors."
        )
        archive_inventory = inspect_zip_attachments(conn, ids, progress=progress)
    digest = config_hash(normalized)
    started = utc_now()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{timestamp}_{uuid.uuid4().hex[:8]}"
    effective_name = (run_name or normalized["name"] or "phish-hunt").strip() or "phish-hunt"
    output_root.mkdir(parents=True, exist_ok=True)
    run_base = _run_base(output_root, effective_name, run_id)
    run_dir: Path | None = staging_directory(run_base)
    selection = _selection_json(start=start, end=end, scope=scope)

    conn.execute(
        """INSERT INTO phish_hunt_runs(
               run_id,case_id,run_name,config_name,config_hash,config_json,selection_json,
               output_path,status,started_utc,message_count,threadsaw_version
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            run_id,
            case_id,
            effective_name,
            normalized["name"],
            digest,
            json.dumps(normalized, sort_keys=True, ensure_ascii=False),
            json.dumps(selection, sort_keys=True),
            str(run_dir),
            "running",
            started,
            len(ids),
            __version__,
        ),
    )
    conn.commit()

    counter = ProgressCounter("PHISH_HUNT", len(ids), progress, every=100)
    scored_count = 0
    report_csv = run_dir / "phish_hunt.csv"
    detail_csv = run_dir / "phish_hunt_details.csv"
    report_json = run_dir / ("phish_hunt.jsonl" if large_case else "phish_hunt.json")
    config_path = run_dir / "scoring_config.json"
    requested_config_path = run_dir / "requested_scoring_config.json"
    manifest_path = run_dir / "run_manifest.json"
    try:
        with report_csv.open("w", encoding="utf-8-sig", newline="") as report_handle, \
             detail_csv.open("w", encoding="utf-8-sig", newline="") as detail_handle, \
             report_json.open("w", encoding="utf-8", newline="\n") as json_handle:
            report_writer = csv.DictWriter(report_handle, fieldnames=PHISH_HUNT_FIELDS, extrasaction="ignore")
            detail_writer = csv.DictWriter(detail_handle, fieldnames=PHISH_HUNT_DETAIL_FIELDS, extrasaction="ignore")
            report_writer.writeheader()
            detail_writer.writeheader()
            if not large_case:
                json_handle.write("[\n")
            first_json = True
            for index, message_sha256 in enumerate(ids, start=1):
                message = conn.execute("SELECT * FROM messages WHERE message_sha256=?", (message_sha256,)).fetchone()
                if not message:
                    counter.update(index, force=index == len(ids))
                    continue
                try:
                    summary, details = evaluate_message(conn, message, normalized)
                except Exception as exc:
                    progress(f"[PHISH_HUNT] ERROR scoring {message_sha256}: {type(exc).__name__}: {exc}")
                    counter.update(index, force=index == len(ids))
                    continue
                summary.update({
                    "phish_hunt_run_id": run_id,
                    "config_name": normalized["name"],
                    "config_hash": digest,
                    "case_id": case_id,
                })
                base = message_rows(conn, [message_sha256])
                if not base:
                    counter.update(index, force=index == len(ids))
                    continue
                merged = {**base[0], **summary}
                report_writer.writerow({key: merged.get(key, "") for key in PHISH_HUNT_FIELDS})
                payload = json.dumps(merged, ensure_ascii=False)
                if large_case:
                    json_handle.write(payload + "\n")
                else:
                    if not first_json:
                        json_handle.write(",\n")
                    json_handle.write("  " + payload)
                    first_json = False
                for detail in details:
                    detail.update({"phish_hunt_run_id": run_id, "case_id": case_id})
                    detail_writer.writerow({key: detail.get(key, "") for key in PHISH_HUNT_DETAIL_FIELDS})

                conn.execute(
                    """INSERT INTO phish_hunt_results(
                           run_id,message_sha256,score,positive_points,negative_points,
                           evaluated_factor_count,unknown_factor_count,max_possible_points_evaluated,
                           unknown_positive_points,positive_score_percent_evaluated,top_score_reasons
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (run_id,message_sha256,summary["score"],summary["positive_points"],summary["negative_points"],
                     summary["evaluated_factor_count"],summary["unknown_factor_count"],
                     summary["max_possible_points_evaluated"],summary["unknown_positive_points"],
                     summary["positive_score_percent_evaluated"],summary["top_score_reasons"]),
                )
                conn.executemany(
                    """INSERT INTO phish_hunt_factor_results(
                           run_id,message_sha256,factor_id,answer,points,weight,effect_mode,
                           evidence,source,status,reason,evaluator_version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [(run_id,d["message_sha256"],d["factor_id"],d["answer"],d["points"],d["weight"],
                      d["effect_mode"],d["evidence"],d["source"],d["status"],d["reason"],d["evaluator_version"])
                     for d in details],
                )
                scored_count += 1
                if index % 250 == 0:
                    conn.commit()
                    report_handle.flush(); detail_handle.flush(); json_handle.flush()
                counter.update(index, force=index == len(ids))
            if not large_case:
                json_handle.write("\n]\n")
        conn.commit()
        atomic_write_json(config_path, normalized)
        atomic_write_json(requested_config_path, requested_config)

        completed = utc_now()
        completion_stamp = completion_timestamp()
        manifest = {
            "project": "Threadsaw",
            "module": "phish_hunt",
            "threadsaw_version": __version__,
            "run_id": run_id,
            "run_name": effective_name,
            "case_id": case_id,
            "status": "complete",
            "started_utc": started,
            "completed_utc": completed,
            "completion_timestamp": completion_stamp,
            "selection": selection,
            "selected_message_count": len(ids),
            "scored_message_count": scored_count,
            "config_name": normalized["name"],
            "config_hash": digest,
            "score_model": "uncapped additive integer centered at zero; the higher the score in the output CSV, the more likely the message is to match the configured phishing indicators",
            "url_auto_indexed_message_count": len(unindexed_ids),
            "archive_inventory": archive_inventory,
            "inferred_case_context": inferred_context,
            "context_dependent_factors_removed": context_removed_factors,
            "reports": {
                "main_csv": report_csv.name,
                "details_csv": detail_csv.name,
                "jsonl" if large_case else "json": report_json.name,
                "configuration": config_path.name,
                "requested_configuration": requested_config_path.name,
            },
        }
        atomic_write_json(manifest_path, manifest)
        final_run_dir = finalize_directory(run_dir, run_base, completion_stamp)
        run_dir = None
        report_csv = final_run_dir / report_csv.name
        detail_csv = final_run_dir / detail_csv.name
        manifest_path = final_run_dir / manifest_path.name
        conn.execute(
            """UPDATE phish_hunt_runs SET status='complete',completed_utc=?,message_count=?,output_path=?
               WHERE run_id=?""",
            (completed, scored_count, str(final_run_dir), run_id),
        )
        conn.commit()
        progress(f"[PHISH_HUNT] Complete: scored={scored_count:,}; output={final_run_dir}")
        return {
            "run_id": run_id,
            "run_directory": str(final_run_dir),
            "completion_timestamp": completion_stamp,
            "selected_messages": len(ids),
            "scored_messages": scored_count,
            "main_report": str(report_csv),
            "details_report": str(detail_csv),
            "manifest": str(manifest_path),
            "config_hash": digest,
            "url_auto_indexed_messages": len(unindexed_ids),
            "archive_inventory": archive_inventory,
            "context_dependent_factors_removed": context_removed_factors,
            "large_case_mode": large_case,
        }
    except Exception as exc:
        completed = utc_now()
        completion_stamp = completion_timestamp()
        conn.rollback()
        final_error_dir = None
        if run_dir is not None:
            atomic_write_json(
                run_dir / "run_manifest.json",
                {
                    "project": "Threadsaw",
                    "module": "phish_hunt",
                    "threadsaw_version": __version__,
                    "run_id": run_id,
                    "case_id": case_id,
                    "status": "error",
                    "started_utc": started,
                    "completed_utc": completed,
                    "completion_timestamp": completion_stamp,
                    "selection": selection,
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
            final_error_dir = finalize_directory(run_dir, run_base, completion_stamp)
            run_dir = None
        conn.execute(
            """UPDATE phish_hunt_runs SET status='error',completed_utc=?,error_detail=?,output_path=? WHERE run_id=?""",
            (completed, f"{type(exc).__name__}: {exc}", str(final_error_dir or run_base), run_id),
        )
        conn.commit()
        raise
    finally:
        cleanup_staging(run_dir)


def list_hunt_runs(conn) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            """SELECT run_id,run_name,config_name,config_hash,selection_json,output_path,status,
                      started_utc,completed_utc,message_count,error_detail
               FROM phish_hunt_runs ORDER BY started_utc DESC,run_id DESC"""
        )
    ]


def read_hunt_report_selection(path: Path, *, min_score: int, case_id: str, conn) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"Phish Hunt report does not exist: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = {str(name or "").strip().lower(): name for name in (reader.fieldnames or [])}
        required = ("message_sha256", "score", "case_id", "phish_hunt_run_id")
        missing = [name for name in required if name not in fields]
        if missing:
            raise ValueError(
                "The selected CSV is not a complete Threadsaw Phish Hunt report; missing column(s): "
                + ", ".join(missing)
            )
        selected: list[str] = []
        seen: set[str] = set()
        run_ids: set[str] = set()
        report_case_ids: set[str] = set()
        for line_number, row in enumerate(reader, start=2):
            report_case_id = str(row.get(fields["case_id"], "")).strip()
            report_case_ids.add(report_case_id)
            run_ids.add(str(row.get(fields["phish_hunt_run_id"], "")).strip())
            value = str(row.get(fields["message_sha256"], "")).strip().lower()
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError(f"Invalid message_sha256 on Phish Hunt report line {line_number}")
            try:
                score = int(str(row.get(fields["score"], "")).strip())
            except ValueError as exc:
                raise ValueError(f"Invalid integer score on Phish Hunt report line {line_number}") from exc
            if score >= min_score and value not in seen:
                selected.append(value)
                seen.add(value)

    if report_case_ids != {case_id}:
        raise ValueError(
            "The Phish Hunt report does not belong to the selected Threadsaw case "
            f"(report case IDs: {sorted(report_case_ids)!r}; selected case ID: {case_id})."
        )
    if len(run_ids) != 1 or "" in run_ids:
        raise ValueError("The Phish Hunt report contains missing or mixed run identifiers")
    if selected:
        existing: set[str] = set()
        for batch in chunked(selected):
            placeholders = ",".join("?" for _ in batch)
            existing.update(
                row["message_sha256"]
                for row in conn.execute(
                    f"SELECT message_sha256 FROM messages WHERE message_sha256 IN ({placeholders})",
                    batch,
                )
            )
        missing_hashes = [value for value in selected if value not in existing]
        if missing_hashes:
            raise ValueError(
                f"The Phish Hunt report selected {len(missing_hashes)} message(s) not present in this case"
            )
    return selected
