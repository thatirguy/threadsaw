"""Infer mailbox-local context from a PST-derived case without user prompts.

Inference is deliberately conservative.  Trusted authentication and Received
boundaries are enabled only when a stable value is repeated across enough
PST-derived messages.  When that consensus is absent, dependent Phish Hunt
factors are removed from the run rather than returning a misleading zero.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime
from email.utils import parseaddr
import math
import re
from pathlib import Path
from typing import Any

from .case import load_case, update_case
from .domains import registrable_domain
from .util import iso_utc, utc_now

BY_HOST_RE = re.compile(r"\bby\s+([^\s();]+)", re.I)
AUTH_FACTOR_IDS = {"trusted_spf_fail", "trusted_dkim_fail", "trusted_dmarc_fail", "trusted_arc_fail"}
RECEIVED_FACTOR_IDS = {"date_received_discrepancy", "sender_ip_new_for_sender"}
MIN_TRUST_CORPUS_MESSAGES = 20
TRUST_CONSENSUS_RATIO = 0.40


def _consensus(counter: Counter[str], total: int) -> list[str]:
    if not counter or total < MIN_TRUST_CORPUS_MESSAGES:
        return []
    top = counter.most_common(1)[0][1]
    minimum = max(3, math.ceil(total * TRUST_CONSENSUS_RATIO))
    if top < minimum:
        return []
    return sorted(value for value, count in counter.items() if count >= minimum and count >= top * 0.5)


def _by_host(raw: str | None) -> str | None:
    match = BY_HOST_RE.search(str(raw or ""))
    if not match:
        return None
    return match.group(1).strip(".[]").lower() or None


def _received_domain_suffixes(host: str | None) -> list[str]:
    """Return parent suffixes bounded by the Public Suffix List registrable unit.

    For a rotating M365 host such as
    ``CH2PR14MB4222.namprd14.prod.outlook.com``, this yields increasingly broad
    stable candidates such as ``namprd14.prod.outlook.com``,
    ``prod.outlook.com``, and ``outlook.com``. Consensus chooses the most
    specific suffix that satisfies the corpus threshold.
    """
    value = str(host or "").strip(".").lower()
    registrable = registrable_domain(value)
    if not value or not registrable:
        return []
    labels = value.split(".")
    registrable_labels = registrable.split(".")
    minimum_index = len(labels) - len(registrable_labels)
    # Exclude the full host; exact-host consensus is attempted first.
    return [".".join(labels[index:]) for index in range(1, minimum_index)] + [registrable]


def _domain_suffix_consensus(counter: Counter[str], total: int) -> list[str]:
    candidates = _consensus(counter, total)
    if not candidates:
        return []
    most_specific = max(value.count(".") for value in candidates)
    return sorted(value for value in candidates if value.count(".") == most_specific)


def _pst_message_join() -> str:
    return """FROM message_sources ms
              JOIN sources s ON s.source_id=ms.source_id
              LEFT JOIN sources parent ON parent.source_id=s.parent_source_id
              WHERE (s.source_type='PST' OR parent.source_type='PST')"""


def _infer_organization_domains(conn) -> list[str]:
    message_count = int(conn.execute(
        "SELECT COUNT(DISTINCT ms.message_sha256) " + _pst_message_join()
    ).fetchone()[0])
    if not message_count:
        return []
    counts: Counter[str] = Counter()
    rows = conn.execute(
        """SELECT r.domain FROM recipients r
           JOIN message_sources ms ON ms.message_sha256=r.message_sha256
           JOIN sources s ON s.source_id=ms.source_id
           LEFT JOIN sources parent ON parent.source_id=s.parent_source_id
           WHERE r.domain IS NOT NULL AND (s.source_type='PST' OR parent.source_type='PST')"""
    )
    for row in rows:
        domain = registrable_domain(row["domain"])
        if domain:
            counts[domain] += 1
    if not counts:
        return []
    top = counts.most_common(1)[0][1]
    minimum = max(2, math.ceil(message_count * 0.15))
    return sorted(domain for domain, count in counts.items() if count >= minimum and count >= top * 0.35)[:10]


def normalize_organization_domains(values: list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize analyst-declared organization domains without any network lookup."""
    normalized: list[str] = []
    for value in values or []:
        for item in re.split(r"[\s,;]+", str(value)):
            domain = registrable_domain(item.strip().lower().lstrip("@"))
            if domain and domain not in normalized:
                normalized.append(domain)
    return normalized


def set_organization_domains(case_dir: Path, values: list[str] | tuple[str, ...] | None) -> list[str]:
    """Replace the case's analyst-declared organization-domain list.

    This setting is intentionally separate from trusted mail-server inference.
    It represents analyst knowledge of the represented organization and is safe
    to provide for PST, EML, or MSG-only cases.
    """
    normalized = normalize_organization_domains(values)
    case_data = load_case(case_dir)
    config = dict(case_data.get("config") or {})
    config["organization_domains"] = normalized
    config["organization_domains_declared"] = bool(normalized)
    case_data["config"] = config
    update_case(case_dir, case_data)
    return normalized


def recompute_case_context(conn, case_dir: Path) -> dict[str, Any]:
    case_data = load_case(case_dir)
    has_pst = bool(conn.execute("SELECT 1 FROM sources WHERE source_type='PST' LIMIT 1").fetchone())
    inferred = dict(case_data.get("inferred_context") or {})
    pst_message_count = int(conn.execute(
        "SELECT COUNT(DISTINCT ms.message_sha256) " + _pst_message_join()
    ).fetchone()[0]) if has_pst else 0

    auth_ids: list[str] = []
    received_hosts: list[str] = []
    received_domains: list[str] = []
    received_match_mode = "unavailable"
    if has_pst and pst_message_count >= MIN_TRUST_CORPUS_MESSAGES:
        auth_counts: Counter[str] = Counter()
        for row in conn.execute(
            """SELECT LOWER(ar.authserv_id) AS authserv_id,COUNT(DISTINCT ar.message_sha256) AS message_count
               FROM authentication_results ar
               JOIN message_sources ms ON ms.message_sha256=ar.message_sha256
               JOIN sources s ON s.source_id=ms.source_id
               LEFT JOIN sources parent ON parent.source_id=s.parent_source_id
               WHERE ar.authserv_id IS NOT NULL AND (s.source_type='PST' OR parent.source_type='PST')
               GROUP BY LOWER(ar.authserv_id)"""
        ):
            auth_counts[str(row["authserv_id"]).strip().lower()] = int(row["message_count"])
        auth_ids = _consensus(auth_counts, pst_message_count)

        received_counts: Counter[str] = Counter()
        received_domain_counts: Counter[str] = Counter()
        for row in conn.execute(
            """SELECT DISTINCT rh.message_sha256,rh.raw_value FROM received_hops rh
               JOIN message_sources ms ON ms.message_sha256=rh.message_sha256
               JOIN sources s ON s.source_id=ms.source_id
               LEFT JOIN sources parent ON parent.source_id=s.parent_source_id
               WHERE rh.hop_order=0 AND (s.source_type='PST' OR parent.source_type='PST')"""
        ):
            host = _by_host(row["raw_value"])
            if host:
                received_counts[host] += 1
                for domain in _received_domain_suffixes(host):
                    received_domain_counts[domain] += 1
        received_hosts = _consensus(received_counts, pst_message_count)
        if received_hosts:
            received_match_mode = "exact-host"
        else:
            received_domains = _domain_suffix_consensus(received_domain_counts, pst_message_count)
            if received_domains:
                received_match_mode = "domain-suffix"

    config = dict(case_data.get("config") or {})
    # Manual trusted-server configuration is intentionally not requested or
    # consumed in 1.2.0.  Only corpus-derived consensus is used.
    config.pop("trusted_authserv_ids", None)
    config.pop("trusted_received_hosts", None)
    org_domains = normalize_organization_domains(config.get("organization_domains", []))
    org_domains_declared = bool(config.get("organization_domains_declared"))
    organization_domain_source = "analyst-declared" if org_domains_declared and org_domains else "unavailable"
    if not org_domains and has_pst:
        org_domains = _infer_organization_domains(conn)
        config["organization_domains"] = org_domains
        config["organization_domains_declared"] = False
        organization_domain_source = "pst-recipient-domain-inference" if org_domains else "unavailable"
    elif org_domains:
        # Preserve compatibility with cases created before the explicit marker
        # existed. Such values are retained rather than discarded.
        organization_domain_source = "analyst-declared" if org_domains_declared else "case-configured-or-prior-inference"

    inferred.update({
        "source": (
            "pst-corpus-consensus" if has_pst and pst_message_count >= MIN_TRUST_CORPUS_MESSAGES
            else "pst-corpus-too-small-for-trust" if has_pst
            else "unavailable-no-pst"
        ),
        "pst_message_count": pst_message_count,
        "minimum_trust_corpus_messages": MIN_TRUST_CORPUS_MESSAGES,
        "trust_consensus_ratio": TRUST_CONSENSUS_RATIO,
        "trusted_authserv_ids": auth_ids,
        "trusted_received_hosts": received_hosts,
        "trusted_received_domains": received_domains,
        "trusted_received_match_mode": received_match_mode,
        "organization_domains": org_domains,
        "organization_domains_source": organization_domain_source,
        "computed_utc": utc_now(),
    })
    case_data["config"] = config
    case_data["inferred_context"] = inferred
    update_case(case_dir, case_data)

    auth_set = set(auth_ids)
    conn.execute("UPDATE authentication_results SET trusted=0")
    if auth_set:
        placeholders = ",".join("?" for _ in auth_set)
        conn.execute(
            f"UPDATE authentication_results SET trusted=1 WHERE LOWER(authserv_id) IN ({placeholders})",
            sorted(auth_set),
        )

    host_set = set(received_hosts)
    received_domain_set = set(received_domains)
    conn.execute("UPDATE received_hops SET trusted=0")
    for row in conn.execute("SELECT hop_id,raw_value FROM received_hops"):
        host = _by_host(row["raw_value"])
        trusted = bool(
            (received_match_mode == "exact-host" and host in host_set)
            or (
                received_match_mode == "domain-suffix"
                and host
                and any(host == domain or host.endswith("." + domain) for domain in received_domain_set)
            )
        )
        if trusted:
            conn.execute("UPDATE received_hops SET trusted=1 WHERE hop_id=?", (row["hop_id"],))

    trusted_dates = {
        row["message_sha256"]: row["parsed_date_utc"]
        for row in conn.execute(
            """SELECT rh.message_sha256,rh.parsed_date_utc
               FROM received_hops rh
               JOIN (
                   SELECT message_sha256,MIN(hop_order) AS first_trusted_hop
                   FROM received_hops WHERE trusted=1 AND parsed_date_utc IS NOT NULL
                   GROUP BY message_sha256
               ) first ON first.message_sha256=rh.message_sha256 AND first.first_trusted_hop=rh.hop_order"""
        )
    }
    message_rows = conn.execute(
        "SELECT message_sha256,header_date_utc,top_received_utc,from_domain_registrable FROM messages"
    ).fetchall()
    date_updates: list[tuple[Any, ...]] = []
    for row in message_rows:
        trusted_date = trusted_dates.get(row["message_sha256"])
        if trusted_date:
            selected, source = trusted_date, "trusted-received-inferred"
        elif row["header_date_utc"]:
            selected, source = row["header_date_utc"], "header"
        elif row["top_received_utc"]:
            selected, source = row["top_received_utc"], "top-received-untrusted"
        else:
            selected, source = None, None
        discrepancy = None
        comparison = trusted_date or row["top_received_utc"]
        if row["header_date_utc"] and comparison:
            try:
                left = datetime.fromisoformat(str(row["header_date_utc"]).replace("Z", "+00:00"))
                right = datetime.fromisoformat(str(comparison).replace("Z", "+00:00"))
                discrepancy = int((left - right).total_seconds())
            except ValueError:
                pass
        date_updates.append((trusted_date, selected, source, discrepancy, row["message_sha256"]))
    conn.executemany(
        "UPDATE messages SET trusted_received_utc=?,selected_date_utc=?,selected_date_source=?,date_discrepancy_seconds=? "
        "WHERE message_sha256=?",
        date_updates,
    )

    org_set = set(org_domains)
    recipient_domains: dict[str, set[str]] = {}
    for item in conn.execute("SELECT message_sha256,domain FROM recipients WHERE domain IS NOT NULL"):
        domain = registrable_domain(item["domain"])
        if domain:
            recipient_domains.setdefault(item["message_sha256"], set()).add(domain)
    direction_updates: list[tuple[str, str]] = []
    for row in message_rows:
        recipients = recipient_domains.get(row["message_sha256"], set())
        sender_internal = bool(row["from_domain_registrable"] in org_set)
        recipient_internal = bool(recipients & org_set)
        if sender_internal and recipient_internal:
            direction = "internal"
        elif sender_internal and not recipient_internal:
            direction = "outbound"
        elif not sender_internal and recipient_internal:
            direction = "inbound"
        else:
            direction = "unknown"
        direction_updates.append((direction, row["message_sha256"]))
    conn.executemany("UPDATE messages SET direction=? WHERE message_sha256=?", direction_updates)
    conn.commit()
    return inferred


def filter_config_for_available_context(config: dict[str, Any], inferred: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    output = deepcopy(config)
    removed: list[dict[str, str]] = []
    auth_available = bool(inferred.get("trusted_authserv_ids"))
    received_available = bool(inferred.get("trusted_received_hosts") or inferred.get("trusted_received_domains"))
    for factor in output.get("factors", []):
        factor_id = factor.get("factor_id")
        reason = None
        if factor_id in AUTH_FACTOR_IDS and not auth_available:
            reason = (
                "No stable trusted Authentication-Results authserv-id could be inferred "
                f"from at least {MIN_TRUST_CORPUS_MESSAGES} PST-derived messages."
            )
        elif factor_id in RECEIVED_FACTOR_IDS and not received_available:
            reason = (
                "No stable trusted Received boundary host or registrable-domain consensus could be inferred "
                f"from at least {MIN_TRUST_CORPUS_MESSAGES} PST-derived messages."
            )
        if reason and factor.get("enabled"):
            factor["enabled"] = False
            removed.append({"factor_id": str(factor_id), "reason": reason})
    return output, removed
