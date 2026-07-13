from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("threadsaw_gui", ROOT / "launcher" / "threadsaw_gui.py")
assert SPEC and SPEC.loader
GUI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUI)


def test_validate_iso_utc_normalizes_offset():
    assert GUI.validate_iso_utc("2026-07-11T10:30:00-04:00") == "2026-07-11T14:30:00Z"


def test_validate_range_rejects_non_increasing_values():
    with pytest.raises(ValueError):
        GUI.validate_range("2026-07-11T12:00:00Z", "2026-07-11T12:00:00Z")


def test_build_compose_command_mounts_input_read_only_and_case(tmp_path):
    evidence = tmp_path / "evidence"
    case = tmp_path / "case"
    ids = tmp_path / "ids.csv"
    evidence.mkdir()
    case.mkdir()
    ids.write_text("message_sha256\n", encoding="utf-8")
    command = GUI.build_compose_command(
        case_dir=str(case),
        input_dir=str(evidence),
        cli_args=["run", "--input", "/input", "--case", "/case"],
        extra_readonly_mounts=[(str(ids), "/selector.csv")],
        container_name="threadsaw-gui-test",
    )
    joined = " ".join(command)
    assert "--name threadsaw-gui-test" in joined
    assert f"{evidence.resolve()}:/input:ro" in joined
    assert f"{case.resolve()}:/case" in joined
    assert f"{ids.resolve()}:/selector.csv:ro" in joined
    assert command[-5:] == ["run", "--input", "/input", "--case", "/case"]


def test_case_container_path_rejects_output_outside_case(tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    inside = case / "exports" / "urls.csv"
    assert GUI.case_container_path(str(inside), str(case)) == "/case/exports/urls.csv"
    with pytest.raises(ValueError):
        GUI.case_container_path(str(tmp_path / "elsewhere.csv"), str(case))


def test_read_scope_names_uses_container_cli_not_host_sqlite(tmp_path, monkeypatch):
    from types import SimpleNamespace

    project = tmp_path / "project"
    case = tmp_path / "case"
    project.mkdir()
    case.mkdir()
    (project / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (case / "threadsaw.sqlite3").write_bytes(b"placeholder")

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["cwd"] = kwargs["cwd"]
        return SimpleNamespace(
            returncode=0,
            stdout='[{"name":"zeta"},{"name":"alpha"}]',
            stderr="",
        )

    monkeypatch.setattr(GUI.subprocess, "run", fake_run)
    assert GUI.read_scope_names(str(project), str(case)) == ["alpha", "zeta"]
    assert captured["cwd"] == project.resolve()
    assert "scope" in captured["command"]
    assert "list" in captured["command"]
    assert "import sqlite3" not in (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")


def test_command_preview_uses_placeholders_and_never_executes(tmp_path):
    command = GUI.build_preview_compose_command(
        case_dir="CASE_OUTPUT_FOLDER",
        input_dir="INPUT_FOLDER",
        cli_args=["run", "--input", "/input", "--case", "/case", "--workers", "4"],
    )
    rendered = GUI.format_command(command)
    assert "threadsaw-gui-preview" in rendered
    assert "INPUT_FOLDER:/input:ro" in rendered
    assert "CASE_OUTPUT_FOLDER:/case" in rendered
    assert rendered.endswith("run --input /input --case /case --workers 4")


def test_progress_start_and_heartbeat_messages_are_stage_aware():
    start = GUI.operation_start_message("run")
    assert "Extraction to EML" in start
    assert "LONG time" in start
    assert GUI.operation_heartbeat_message("extraction").startswith("Still working on extraction")
    assert GUI.stage_from_progress_line("extraction", "[PST] Extraction complete: 100 EML files") == "message indexing"
    assert GUI.stage_from_progress_line("message indexing", "[PIPELINE] URL indexing starting") == "URL indexing"
    assert GUI.stage_from_progress_line("URL indexing", "[PIPELINE] Report generation starting") == "report generation"


def test_compose_does_not_define_default_evidence_or_case_directories():
    compose_text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "volumes:" not in compose_text
    assert not (ROOT / "evidence").exists()


def test_discover_phish_hunt_reports_returns_newest_first(tmp_path):
    first = tmp_path / "reports" / "phish_hunt" / "run-a" / "phish_hunt.csv"
    second = tmp_path / "reports" / "phish_hunt" / "run-b" / "phish_hunt.csv"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("message_sha256,score\n", encoding="utf-8")
    second.write_text("message_sha256,score\n", encoding="utf-8")
    first.touch()
    import os
    os.utime(first, (1, 1))
    os.utime(second, (2, 2))
    assert GUI.discover_phish_hunt_reports(str(tmp_path)) == [str(second), str(first)]


def test_phish_hunt_config_supports_unbounded_integer_weight():
    document = GUI.phish_hunt_config_document(
        name="Custom",
        enabled=True,
        weight=10_000_000,
        effect_mode="bidirectional_trust",
    )
    factor = document["factors"][0]
    assert factor["weight"] == 10_000_000
    assert factor["effect_mode"] == "bidirectional_trust"


def test_workflow_dashboard_and_phish_guidance_are_present_and_init_removed():
    source = (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")
    assert "Step 1: Data Initialization" in source
    assert "Step 2: Deeper Analysis and Exports" in source
    for label in (
        "Full Pipeline",
        "Ingest Data",
        "Generate Reports",
        "Set Scope",
        "Phish Hunt",
        "Get URLs",
        "Export Attachments",
    ):
        assert f'label="{label}"' in source or f'_new_tab("{label}")' in source
    assert "No emails are omitted from the report" in source
    assert "Initialize case" not in source
    assert "run_init" not in source


def test_tabs_are_scrollable_and_visually_emphasized():
    source = (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")
    assert "class ScrollableTab" in source
    assert "two-row module tab bar" in source
    assert "self.tab_nav_rows" in source
    assert 'font=("TkDefaultFont", 10, "bold")' in source


def test_attachment_tab_has_distinct_report_and_export_actions():
    source = (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")
    assert "Generate Attachment Report Only" in source
    assert "Generate Report and Export Attachment Files" in source
    assert "Copy attachment bytes into an analyst-friendly export tree" not in source
    assert "def run_attachments_report" in source
    assert "def run_attachments_export" in source
    assert 'action in {"run_attachments_report", "run_attachments_export"}' in source


def test_factor_catalog_ui_has_collapsible_groups_help_and_load_badges():
    source = (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")
    assert "class CollapsibleSection" in source
    assert "class FactorInfoDialog" in source
    assert "class HoverToolTip" in source
    assert "Click for more information." in source
    assert "Search factors" in source
    assert "Inherently Risky" in (ROOT / "src" / "threadsaw" / "factor_catalog.py").read_text(encoding="utf-8") or "inherently_risky" in source
    assert "Computational load" in source
    assert "Evaluator pending" in source


def test_catalog_contains_both_categories_and_approved_factor_metadata():
    assert len(GUI.FACTOR_CATALOG) >= 50
    categories = {item["top_category"] for item in GUI.FACTOR_CATALOG}
    assert categories == {"inherently_risky", "situational"}
    factor = next(item for item in GUI.FACTOR_CATALOG if item["factor_id"] == "displayed_url_domain_mismatch")
    assert factor["load"] in GUI.LOAD_LEVELS
    assert "rewrit" in factor["false_positive_notes"].lower()


def test_new_modules_and_attachment_extension_filter_are_exposed():
    source = (ROOT / "launcher" / "threadsaw_gui.py").read_text(encoding="utf-8")
    assert '_new_tab("String Search")' in source
    assert '_new_tab("Evaluate Phishing Email")' in source
    assert 'label="String Search"' in source
    assert 'label="Evaluate Phishing Email"' in source
    assert "Optional filename-extension filter" in source
    assert "Export config.json…" in source
    assert "Import config.json…" in source


def test_discover_exported_message_text_folder_prefers_latest_run(tmp_path):
    first = tmp_path / "exports" / "message-export_20260101T000000Z" / "One" / "review.txt"
    second = tmp_path / "exports" / "message-export_20260102T000000Z" / "Two" / "review.txt"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("one", encoding="utf-8")
    second.write_text("two", encoding="utf-8")
    import os
    os.utime(first, (1, 1))
    os.utime(second, (2, 2))
    assert GUI.discover_exported_message_text_folder(str(tmp_path)) == str(second.parents[1])
