"""Starter Phish Hunt configurations.

The presets are intentionally conservative heuristics, not calibrated risk
models. They exist to give analysts a usable starting point that can be
reviewed, edited, exported, and versioned before execution.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from .factor_catalog import FACTOR_CATALOG

CONFIG_VERSION = 1

PRESET_LABELS = {
    "external": "External phishing email hunt",
    "internal": "Internal phishing email hunt",
    "general": "General phishing email hunt",
}


def _r(weight: int) -> tuple[int, str]:
    return weight, "risk_when_yes"


def _t(weight: int) -> tuple[int, str]:
    return weight, "trust_when_yes"


# Only factors listed below are enabled. All other visible factors remain off
# with a zero weight. Factors requiring organization-specific input (for
# example, legitimate domains or a SharePoint host) are deliberately left off.
EXTERNAL_OVERRIDES: dict[str, tuple[int, str]] = {
    # Inherently risky
    "reply_to_domain_mismatch": _r(25),
    "display_name_embedded_email_domain_mismatch": _r(35),
    "sender_domain_lookalike_recipient": _r(35),
    "trusted_dmarc_fail": _r(30),
    "trusted_dkim_fail": _r(25),
    "trusted_spf_fail": _r(15),
    "displayed_url_domain_mismatch": _r(30),
    "url_literal_ip": _r(30),
    "url_userinfo_misdirection": _r(40),
    "url_nonstandard_port": _r(15),
    "url_dangerous_scheme": _r(40),
    "url_obfuscated_numeric_ip": _r(40),
    "attachment_executable_or_script": _r(50),
    "attachment_double_extension": _r(35),
    "attachment_unicode_controls": _r(35),
    "executable_without_extension": _r(45),
    "attachment_shortcut": _r(45),
    "attachment_disk_image": _r(30),
    "attachment_html_svg": _r(40),
    "attachment_modern_loader_or_macro": _r(45),
    "html_form": _r(35),
    "html_auto_redirect": _r(35),
    "html_embedded_active_object": _r(40),
    "html_script": _r(45),
    "html_event_handlers": _r(25),
    # Situational
    "return_path_domain_mismatch": _r(10),
    "sender_address_new": _r(10),
    "sender_domain_new": _r(15),
    "reply_to_new_for_sender": _r(15),
    "return_path_new_for_sender": _r(5),
    "sender_free_email_provider": _r(8),
    "sender_domain_punycode": _r(20),
    "sender_header_mismatch": _r(10),
    "corroborated_thread_reply": _t(5),
    "thread_continuation_changed_infrastructure": _r(35),
    "payment_urgency_keywords": _r(15),
    "prior_sender_recipient": _t(10),
    "prior_sender_subject": _t(5),
    "reply_subject_without_references": _r(10),
    "unmatched_thread_references": _r(10),
    "trusted_arc_fail": _r(5),
    "authentication_conflict": _r(15),
    "date_received_discrepancy": _r(10),
    "message_id_missing_or_malformed": _r(5),
    "message_id_domain_mismatch": _r(5),
    "url_shortener": _r(10),
    "url_punycode": _r(20),
    "url_domain_new_case": _r(10),
    "url_domain_new_sender": _r(10),
    "url_deep_subdomains": _r(10),
    "url_nested_url": _r(10),
    "url_plain_http": _r(5),
    "url_heavy_percent_encoding": _r(5),
    "url_base64_like": _r(5),
    "url_contains_recipient_email": _r(10),
    "url_domain_differs_sender": _r(5),
    "attachment_type_new_sender": _r(10),
    "attachment_archive": _r(10),
    "attachment_encrypted_zip": _r(25),
    "attached_email": _r(5),
    "sender_recipient_same_domain": _t(15),
    "sender_mimics_recipient_localpart": _r(20),
    "no_visible_recipient": _r(5),
    "bcc_only_recipients": _r(5),
}

INTERNAL_OVERRIDES: dict[str, tuple[int, str]] = {
    # Inherently risky
    "reply_to_domain_mismatch": _r(25),
    "display_name_embedded_email_domain_mismatch": _r(30),
    "sender_domain_lookalike_recipient": _r(25),
    "trusted_dmarc_fail": _r(20),
    "trusted_dkim_fail": _r(25),
    "trusted_spf_fail": _r(15),
    "displayed_url_domain_mismatch": _r(30),
    "url_literal_ip": _r(30),
    "url_userinfo_misdirection": _r(40),
    "url_nonstandard_port": _r(15),
    "url_dangerous_scheme": _r(40),
    "url_obfuscated_numeric_ip": _r(40),
    "attachment_executable_or_script": _r(50),
    "attachment_double_extension": _r(35),
    "attachment_unicode_controls": _r(35),
    "executable_without_extension": _r(45),
    "attachment_shortcut": _r(45),
    "attachment_disk_image": _r(30),
    "attachment_html_svg": _r(40),
    "attachment_modern_loader_or_macro": _r(45),
    "html_form": _r(35),
    "html_auto_redirect": _r(35),
    "html_embedded_active_object": _r(40),
    "html_script": _r(45),
    "html_event_handlers": _r(25),
    # Situational
    "return_path_domain_mismatch": _r(10),
    "sender_address_new": _r(5),
    "sender_ip_new_for_sender": _r(10),
    "reply_to_new_for_sender": _r(20),
    "return_path_new_for_sender": _r(10),
    "sender_domain_punycode": _r(15),
    "sender_header_mismatch": _r(10),
    "corroborated_thread_reply": _t(5),
    "thread_continuation_changed_infrastructure": _r(40),
    "payment_urgency_keywords": _r(20),
    "reply_subject_without_references": _r(10),
    "unmatched_thread_references": _r(10),
    "trusted_arc_fail": _r(5),
    "authentication_conflict": _r(15),
    "date_received_discrepancy": _r(10),
    "message_id_missing_or_malformed": _r(5),
    "message_id_domain_mismatch": _r(5),
    "url_shortener": _r(10),
    "url_punycode": _r(20),
    "url_domain_new_case": _r(5),
    "url_domain_new_sender": _r(15),
    "url_deep_subdomains": _r(10),
    "url_nested_url": _r(10),
    "url_plain_http": _r(5),
    "url_heavy_percent_encoding": _r(5),
    "url_base64_like": _r(5),
    "url_contains_recipient_email": _r(10),
    "url_domain_differs_sender": _r(5),
    "attachment_type_new_sender": _r(15),
    "attachment_archive": _r(10),
    "attachment_encrypted_zip": _r(20),
    "attached_email": _r(5),
    "sender_recipient_same_domain": _r(25),
    "sender_mimics_recipient_localpart": _r(15),
    "no_visible_recipient": _r(5),
    "bcc_only_recipients": _r(5),
}

GENERAL_OVERRIDES: dict[str, tuple[int, str]] = {
    # Inherently risky
    "reply_to_domain_mismatch": _r(25),
    "display_name_embedded_email_domain_mismatch": _r(35),
    "sender_domain_lookalike_recipient": _r(30),
    "trusted_dmarc_fail": _r(30),
    "trusted_dkim_fail": _r(25),
    "trusted_spf_fail": _r(15),
    "displayed_url_domain_mismatch": _r(30),
    "url_literal_ip": _r(30),
    "url_userinfo_misdirection": _r(40),
    "url_nonstandard_port": _r(15),
    "url_dangerous_scheme": _r(40),
    "url_obfuscated_numeric_ip": _r(40),
    "attachment_executable_or_script": _r(50),
    "attachment_double_extension": _r(35),
    "attachment_unicode_controls": _r(35),
    "executable_without_extension": _r(45),
    "attachment_shortcut": _r(45),
    "attachment_disk_image": _r(30),
    "attachment_html_svg": _r(40),
    "attachment_modern_loader_or_macro": _r(45),
    "html_form": _r(35),
    "html_auto_redirect": _r(35),
    "html_embedded_active_object": _r(40),
    "html_script": _r(45),
    "html_event_handlers": _r(25),
    # Situational
    "return_path_domain_mismatch": _r(10),
    "sender_address_new": _r(5),
    "sender_domain_new": _r(10),
    "reply_to_new_for_sender": _r(10),
    "return_path_new_for_sender": _r(5),
    "sender_free_email_provider": _r(8),
    "sender_domain_punycode": _r(15),
    "sender_header_mismatch": _r(10),
    "corroborated_thread_reply": _t(5),
    "thread_continuation_changed_infrastructure": _r(35),
    "payment_urgency_keywords": _r(15),
    "prior_sender_recipient": _t(5),
    "prior_sender_subject": _t(5),
    "reply_subject_without_references": _r(10),
    "unmatched_thread_references": _r(10),
    "trusted_arc_fail": _r(5),
    "authentication_conflict": _r(15),
    "date_received_discrepancy": _r(10),
    "message_id_missing_or_malformed": _r(5),
    "message_id_domain_mismatch": _r(5),
    "url_shortener": _r(5),
    "url_punycode": _r(15),
    "url_domain_new_case": _r(5),
    "url_domain_new_sender": _r(10),
    "url_deep_subdomains": _r(10),
    "url_nested_url": _r(10),
    "url_plain_http": _r(5),
    "url_heavy_percent_encoding": _r(5),
    "url_base64_like": _r(5),
    "url_contains_recipient_email": _r(5),
    "url_domain_differs_sender": _r(5),
    "attachment_type_new_sender": _r(10),
    "attachment_archive": _r(10),
    "attachment_encrypted_zip": _r(25),
    "attached_email": _r(5),
    "sender_mimics_recipient_localpart": _r(20),
    "no_visible_recipient": _r(5),
    "bcc_only_recipients": _r(5),
}

PRESET_OVERRIDES = {
    "external": EXTERNAL_OVERRIDES,
    "internal": INTERNAL_OVERRIDES,
    "general": GENERAL_OVERRIDES,
}


def _default_parameters(metadata: dict[str, Any]) -> dict[str, Any]:
    return {item["name"]: deepcopy(item.get("default", "")) for item in metadata.get("parameters", [])}


def preset_config(name: str) -> dict[str, Any]:
    """Return a complete config.json document for a starter preset.

    ``name`` accepts the short names external/internal/general, their full GUI
    labels, or clear. The returned document includes every visible factor so
    it can be exported directly and reviewed without hidden defaults.
    """
    normalized = str(name or "").strip().casefold()
    aliases = {label.casefold(): slug for slug, label in PRESET_LABELS.items()}
    slug = aliases.get(normalized, normalized)
    if slug == "clear":
        label = "Clear"
        overrides: dict[str, tuple[int, str]] = {}
    elif slug in PRESET_OVERRIDES:
        label = PRESET_LABELS[slug]
        overrides = PRESET_OVERRIDES[slug]
    else:
        raise ValueError(f"Unknown Phish Hunt preset: {name}")

    catalog_ids = {item["factor_id"] for item in FACTOR_CATALOG}
    unknown = sorted(set(overrides) - catalog_ids)
    if unknown:
        raise RuntimeError(f"Preset {slug} references unknown factors: {', '.join(unknown)}")

    factors = []
    for metadata in FACTOR_CATALOG:
        factor_id = metadata["factor_id"]
        enabled = factor_id in overrides
        weight, effect_mode = overrides.get(factor_id, (0, "risk_when_yes"))
        factors.append({
            "factor_id": factor_id,
            "enabled": enabled,
            "weight": weight,
            "effect_mode": effect_mode,
            "parameters": _default_parameters(metadata),
        })
    return {
        "config_version": CONFIG_VERSION,
        "name": label,
        "preset": slug,
        "factors": factors,
        "notes": (
            "Starter heuristic preset supplied with Threadsaw. It is not a calibrated probability model. "
            "Review enabled factors, weights, effect directions, and organization-specific parameters before use."
        ),
    }


def available_presets() -> list[dict[str, str]]:
    return [{"name": slug, "label": label} for slug, label in PRESET_LABELS.items()]
