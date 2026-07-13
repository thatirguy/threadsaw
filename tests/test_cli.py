from __future__ import annotations

import sys

import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.cli import build_parser


def test_export_messages_accepts_date_range_as_standalone_selector():
    args = build_parser().parse_args([
        "export-messages",
        "--case", "/case",
        "--output", "/case/exports/date-range",
        "--start", "2026-07-09T12:59:08Z",
        "--end", "2026-07-12T12:59:22Z",
    ])
    assert args.command == "export-messages"
    assert args.start == "2026-07-09T12:59:08Z"
    assert args.end == "2026-07-12T12:59:22Z"
    assert not args.all_messages


def test_phish_hunt_accepts_date_or_scope_and_analysis_accepts_threshold_report():
    args = build_parser().parse_args([
        "phish-hunt",
        "--case", "/case",
        "--start", "2026-07-01T00:00:00Z",
        "--end", "2026-07-08T00:00:00Z",
        "--run-name", "Prototype hunt",
    ])
    assert args.command == "phish-hunt"
    assert args.scope is None

    url_args = build_parser().parse_args([
        "urls",
        "--case", "/case",
        "--phish-hunt-report", "/report/phish_hunt.csv",
        "--min-score", "-25",
    ])
    assert url_args.phish_hunt_report == Path("/report/phish_hunt.csv")
    assert url_args.min_score == -25


def test_public_init_command_is_removed():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["init", "--case", "/case"])


def test_phish_hunt_preset_cli_accepts_bundled_names(tmp_path):
    output = tmp_path / "general.json"
    args = build_parser().parse_args([
        "phish-hunt-preset",
        "--name", "general",
        "--output", str(output),
    ])
    assert args.command == "phish-hunt-preset"
    assert args.name == "general"
    assert args.output == output
