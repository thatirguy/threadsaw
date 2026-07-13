"""Cross-platform desktop launcher for Threadsaw.

The launcher orchestrates the existing Docker Compose CLI. It displays command
progress and outcomes only; it does not display email contents or generated
case data, and it never opens attachments, URLs, or IP addresses.

No third-party GUI dependency is required. The UTC date/time picker is built
with the Python standard library's Tkinter, calendar, and datetime modules.
"""
from __future__ import annotations

import calendar
import json
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from threadsaw.factor_catalog import FACTOR_CATALOG, LOAD_LEVELS, TOP_CATEGORY_LABELS
from threadsaw.phish_hunt_presets import preset_config

APP_TITLE = "Threadsaw 1.3.0"
MOTTO = "When you're looking for a needle in a haystack, you need a pitchfork."
DEFAULT_GEOMETRY = "1020x820"
SELECTOR_OPTIONS = (
    "All messages",
    "Date range",
    "One message SHA-256",
    "SHA-256 CSV",
    "Named scope",
)
PHISH_HUNT_REPORT_SELECTOR = "Phish Hunt report threshold"
PHISH_HUNT_EFFECT_OPTIONS = (
    "Risk when Yes (Yes +weight / No 0)",
    "Trust when Yes (Yes -weight / No 0)",
    "Bidirectional risk (Yes +weight / No -weight)",
    "Bidirectional trust (Yes -weight / No +weight)",
)
PHISH_HUNT_EFFECT_VALUES = {
    PHISH_HUNT_EFFECT_OPTIONS[0]: "risk_when_yes",
    PHISH_HUNT_EFFECT_OPTIONS[1]: "trust_when_yes",
    PHISH_HUNT_EFFECT_OPTIONS[2]: "bidirectional_risk",
    PHISH_HUNT_EFFECT_OPTIONS[3]: "bidirectional_trust",
}
HEARTBEAT_INTERVAL_MS = 90_000

START_MESSAGES = {
    "run": (
        "Extraction to EML and indexing of messages, URLs, and attachments starting. "
        "This can take a LONG time for larger PST files."
    ),
    "ingest": (
        "Input discovery, PST extraction, and message indexing starting. "
        "This can take a LONG time for larger PST files."
    ),
    "report": "Report generation starting.",
    "urls": "Offline URL-string indexing and report generation starting.",
    "attachments": "Attachment reporting and optional inert-byte copying starting.",
    "export-messages": "Selected message export starting.",
    "scope": "Named-scope operation starting.",
    "doctor": "Case and runtime diagnostics starting.",
    "phish-hunt": "Phish Hunt scoring starting. A unique report folder will be created for this execution.",
    "phish-hunt-list": "Listing prior Phish Hunt runs recorded in the selected case.",
    "string-search": "Case-insensitive literal string search starting across the selected local data sources.",
    "evaluate-phishing-email": "Evaluating one email against all relevant Phish Hunt factors. No URL, IP address, or attachment will be opened or contacted.",
}


def operation_start_message(operation: str) -> str:
    return START_MESSAGES.get(operation, "Threadsaw operation starting.")


def initial_operation_stage(operation: str) -> str:
    return {
        "run": "extraction",
        "ingest": "extraction",
        "urls": "URL indexing",
        "attachments": "attachment reporting",
        "export-messages": "message export",
        "report": "report generation",
        "scope": "scope processing",
        "doctor": "diagnostics",
        "phish-hunt": "Phish Hunt scoring",
        "phish-hunt-list": "Phish Hunt run listing",
        "string-search": "string search",
        "evaluate-phishing-email": "email factor evaluation",
    }.get(operation, "processing")


def stage_from_progress_line(current: str, line: str) -> str:
    text = line.lower()
    if "[pst] starting readpst" in text:
        return "extraction"
    if "[pst] extraction complete" in text or "[index]" in text:
        return "message indexing"
    if "[pipeline] url indexing starting" in text or "[urls]" in text:
        return "URL indexing"
    if "[pipeline] report generation starting" in text or "[report]" in text:
        return "report generation"
    if "[attachments]" in text:
        return "attachment reporting"
    if "[export]" in text:
        return "message export"
    if "[phish_hunt]" in text:
        return "Phish Hunt scoring"
    if "[string_search]" in text:
        return "string search"
    if "[evaluate_email]" in text:
        return "email factor evaluation"
    return current


def operation_heartbeat_message(stage: str) -> str:
    if stage == "extraction":
        return "Still working on extraction. Large PST files can take a long time."
    return f"Still working on {stage}."


def validate_iso_utc(value: str) -> str:
    """Validate an ISO-8601 timestamp and return a normalized UTC Z value."""
    text = value.strip()
    if not text:
        raise ValueError("Date/time is blank.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            "Use ISO 8601 with a timezone, for example 2026-07-11T14:30:00Z."
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError("A timezone is required. Use Z for UTC or include an offset.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_range(start: str, end: str, *, required: bool = True) -> tuple[str | None, str | None]:
    """Validate a start-inclusive/end-exclusive date range."""
    start_text = start.strip()
    end_text = end.strip()
    if not start_text and not end_text and not required:
        return None, None
    if not start_text or not end_text:
        raise ValueError("Both start and end date/time values are required.")
    start_utc = validate_iso_utc(start_text)
    end_utc = validate_iso_utc(end_text)
    start_dt = datetime.fromisoformat(start_utc.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_utc.replace("Z", "+00:00"))
    if start_dt >= end_dt:
        raise ValueError("The end date/time must be later than the start date/time.")
    return start_utc, end_utc


def path_within(path: Path, parent: Path) -> Path | None:
    """Return a path relative to parent, or None when path is outside parent."""
    try:
        return path.resolve().relative_to(parent.resolve())
    except ValueError:
        return None


def case_container_path(host_path: str, case_dir: str) -> str:
    """Translate a host path inside the selected case directory to /case."""
    relative = path_within(Path(host_path), Path(case_dir))
    if relative is None:
        raise ValueError("The selected output must be inside the case/output folder.")
    return "/case" if str(relative) == "." else "/case/" + relative.as_posix()


def read_scope_names(project_dir: str, case_dir: str, *, timeout: int = 45) -> list[str]:
    """Ask the Threadsaw container for scope names; never open SQLite on the host."""
    project = Path(project_dir).expanduser().resolve()
    case = Path(case_dir).expanduser().resolve()
    if not (project / "compose.yaml").is_file() or not (case / "threadsaw.sqlite3").is_file():
        return []
    command = build_compose_command(
        case_dir=str(case),
        cli_args=["--quiet", "scope", "list", "--case", "/case"],
        container_name=f"threadsaw-scope-list-{uuid.uuid4().hex[:10]}",
    )
    try:
        result = subprocess.run(
            command,
            cwd=project,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not refresh named scopes through Docker: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown Docker error").strip()
        raise RuntimeError(f"Could not refresh named scopes: {detail}")
    try:
        rows = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Threadsaw returned invalid scope-list output") from exc
    if not isinstance(rows, list):
        raise RuntimeError("Threadsaw returned an unexpected scope-list response")
    return sorted(str(row.get("name")) for row in rows if isinstance(row, dict) and row.get("name"))


def discover_phish_hunt_reports(case_dir: str) -> list[str]:
    """List existing Phish Hunt main CSV reports without opening their contents."""
    value = case_dir.strip()
    if not value:
        return []
    root = Path(value).expanduser().resolve() / "reports"
    if not root.is_dir():
        return []
    reports = [path for path in root.rglob("phish_hunt.csv") if path.is_file()]
    reports.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return [str(path) for path in reports]


def discover_exported_message_text_folder(case_dir: str) -> str:
    """Return the newest export folder containing Threadsaw review TXT files."""
    value = case_dir.strip()
    if not value:
        return ""
    root = Path(value).expanduser().resolve() / "exports"
    if not root.is_dir():
        return ""
    candidates: dict[Path, float] = {}
    for review in root.rglob("review.txt"):
        if not review.is_file():
            continue
        # review.txt normally lives one level below a completed message-export
        # folder. Walk upward only until the exports root and choose the first
        # folder whose name resembles a completed message export.
        folder = review.parent
        for parent in [folder, *folder.parents]:
            if parent == root.parent:
                break
            if parent.parent == root or parent.name.startswith("message-export_"):
                folder = parent
                break
        candidates[folder] = max(candidates.get(folder, 0.0), review.stat().st_mtime)
    if not candidates:
        return ""
    return str(max(candidates, key=candidates.get))


def phish_hunt_config_document(
    *,
    name: str,
    factors: list[dict[str, Any]] | None = None,
    enabled: bool | None = None,
    weight: int | None = None,
    effect_mode: str | None = None,
) -> dict:
    """Build a versioned Phish Hunt configuration document.

    ``enabled``/``weight``/``effect_mode`` remain accepted for the legacy
    single-factor launcher tests.  New GUI code passes the full catalog list.
    """
    if factors is None:
        legacy_weight = 0 if weight is None else weight
        legacy_effect = effect_mode or "risk_when_yes"
        if legacy_weight < 0:
            raise ValueError("Factor weight must be zero or greater. Score direction is controlled by the effect setting.")
        if legacy_effect not in PHISH_HUNT_EFFECT_VALUES.values():
            raise ValueError("Choose a valid factor effect.")
        factors = [{
            "factor_id": "sender_recipient_same_domain",
            "enabled": bool(enabled),
            "weight": int(legacy_weight),
            "effect_mode": legacy_effect,
            "parameters": {},
        }]
    for item in factors:
        item_weight = item.get("weight", 0)
        if isinstance(item_weight, bool) or not isinstance(item_weight, int) or item_weight < 0:
            raise ValueError(f"Factor {item.get('factor_id', '[blank]')} weight must be a non-negative integer.")
        if item.get("effect_mode") not in PHISH_HUNT_EFFECT_VALUES.values():
            raise ValueError(f"Factor {item.get('factor_id', '[blank]')} has an invalid effect setting.")
    return {
        "config_version": 1,
        "name": name.strip() or "Custom",
        "preset": name.strip() or "custom",
        "factors": factors,
    }


def _validated_mount_host_path(value: str) -> str:
    resolved = str(Path(value).resolve())
    colon_positions = [index for index, char in enumerate(resolved) if char == ":"]
    allowed_drive_colon = len(resolved) >= 3 and resolved[1] == ":" and resolved[2] in {"\\", "/"}
    unexpected = [index for index in colon_positions if not (allowed_drive_colon and index == 1)]
    if unexpected:
        raise ValueError(
            "Docker bind-mount host paths containing ':' are not supported by this launcher because Docker may misparse them. "
            "Move the folder to a path without a colon and try again."
        )
    return resolved


def build_compose_command(
    *,
    case_dir: str,
    cli_args: list[str],
    input_dir: str | None = None,
    extra_readonly_mounts: list[tuple[str, str]] | None = None,
    container_name: str | None = None,
) -> list[str]:
    """Build a Docker Compose command without invoking a shell."""
    name = container_name or f"threadsaw-gui-{uuid.uuid4().hex[:10]}"
    command = ["docker", "compose", "run", "--rm", "--no-deps", "-T", "--name", name]
    if input_dir:
        command += ["-v", f"{_validated_mount_host_path(input_dir)}:/input:ro"]
    command += ["-v", f"{_validated_mount_host_path(case_dir)}:/case"]
    for host_path, container_path in extra_readonly_mounts or []:
        command += ["-v", f"{_validated_mount_host_path(host_path)}:{container_path}:ro"]
    command += ["threadsaw", *cli_args]
    return command


def build_preview_compose_command(
    *,
    case_dir: str,
    cli_args: list[str],
    input_dir: str | None = None,
    extra_readonly_mounts: list[tuple[str, str]] | None = None,
) -> list[str]:
    """Build a non-executed teaching preview, allowing placeholder paths."""
    command = ["docker", "compose", "run", "--rm", "--no-deps", "-T", "--name", "threadsaw-gui-preview"]
    if input_dir:
        command += ["-v", f"{input_dir}:/input:ro"]
    command += ["-v", f"{case_dir}:/case"]
    for host_path, container_path in extra_readonly_mounts or []:
        command += ["-v", f"{host_path}:{container_path}:ro"]
    command += ["threadsaw", *cli_args]
    return command


def format_command(command: list[str]) -> str:
    """Render an argument-list command for display only; never execute a shell."""
    return subprocess.list2cmdline(command)


class CalendarDialog(tk.Toplevel):
    """Small dependency-free UTC calendar and time selector."""

    def __init__(self, parent: tk.Widget, initial: str, callback: Callable[[str], None], title: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent.winfo_toplevel())
        self.grab_set()
        self.callback = callback

        parsed = self._parse_initial(initial)
        self.selected_date = parsed.date()
        self.visible_year = parsed.year
        self.visible_month = parsed.month
        self.hour = tk.StringVar(value=f"{parsed.hour:02d}")
        self.minute = tk.StringVar(value=f"{parsed.minute:02d}")
        self.second = tk.StringVar(value=f"{parsed.second:02d}")
        self.month_label = tk.StringVar()

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Button(header, text="◀", width=3, command=self._previous_month).pack(side="left")
        ttk.Label(header, textvariable=self.month_label, anchor="center", width=24).pack(side="left", expand=True)
        ttk.Button(header, text="▶", width=3, command=self._next_month).pack(side="right")

        self.calendar_frame = ttk.Frame(outer)
        self.calendar_frame.pack(fill="both", expand=True, pady=(8, 4))
        self.selection_label = tk.StringVar()
        ttk.Label(outer, textvariable=self.selection_label, anchor="center").pack(fill="x", pady=(0, 4))

        time_frame = ttk.LabelFrame(outer, text="UTC time", padding=8)
        time_frame.pack(fill="x", pady=(6, 0))
        ttk.Label(time_frame, text="Hour").grid(row=0, column=0, padx=(0, 4))
        ttk.Combobox(time_frame, textvariable=self.hour, values=[f"{x:02d}" for x in range(24)], width=4, state="readonly").grid(row=0, column=1)
        ttk.Label(time_frame, text=":").grid(row=0, column=2)
        ttk.Combobox(time_frame, textvariable=self.minute, values=[f"{x:02d}" for x in range(60)], width=4, state="readonly").grid(row=0, column=3)
        ttk.Label(time_frame, text=":").grid(row=0, column=4)
        ttk.Combobox(time_frame, textvariable=self.second, values=[f"{x:02d}" for x in range(60)], width=4, state="readonly").grid(row=0, column=5)

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Today", command=self._today).pack(side="left")
        ttk.Button(actions, text="Cancel", command=self.destroy).pack(side="right")
        ttk.Button(actions, text="Use selection", command=self._accept).pack(side="right", padx=(0, 8))

        self._draw_calendar()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.wait_visibility()
        self.focus_set()

    @staticmethod
    def _parse_initial(value: str) -> datetime:
        try:
            if value.strip():
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return now

    def _previous_month(self) -> None:
        self.visible_month -= 1
        if self.visible_month == 0:
            self.visible_month = 12
            self.visible_year -= 1
        self._draw_calendar()

    def _next_month(self) -> None:
        self.visible_month += 1
        if self.visible_month == 13:
            self.visible_month = 1
            self.visible_year += 1
        self._draw_calendar()

    def _today(self) -> None:
        today = datetime.now(timezone.utc)
        self.selected_date = today.date()
        self.visible_year = today.year
        self.visible_month = today.month
        self._draw_calendar()

    def _choose_day(self, day: int) -> None:
        self.selected_date = date(self.visible_year, self.visible_month, day)
        self._draw_calendar()

    def _draw_calendar(self) -> None:
        for child in self.calendar_frame.winfo_children():
            child.destroy()
        self.month_label.set(f"{calendar.month_name[self.visible_month]} {self.visible_year}")
        for column, name in enumerate(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")):
            ttk.Label(self.calendar_frame, text=name, anchor="center", width=5).grid(row=0, column=column, padx=1, pady=1)
        weeks = calendar.Calendar(firstweekday=calendar.MONDAY).monthdayscalendar(self.visible_year, self.visible_month)
        for row, week in enumerate(weeks, start=1):
            for column, day in enumerate(week):
                if day == 0:
                    ttk.Label(self.calendar_frame, text="", width=5).grid(row=row, column=column, padx=1, pady=1)
                    continue
                selected = self.selected_date == date(self.visible_year, self.visible_month, day)
                options = {
                    "text": str(day),
                    "width": 4,
                    "command": lambda value=day: self._choose_day(value),
                    "relief": tk.SUNKEN if selected else tk.RAISED,
                    "borderwidth": 2 if selected else 1,
                }
                if selected:
                    options.update({"background": "#2f6fed", "foreground": "white", "activebackground": "#2f6fed", "activeforeground": "white"})
                tk.Button(self.calendar_frame, **options).grid(row=row, column=column, padx=1, pady=1)
        self.selection_label.set(f"Selected date: {self.selected_date.isoformat()} (UTC)")

    def _accept(self) -> None:
        value = datetime(
            self.selected_date.year,
            self.selected_date.month,
            self.selected_date.day,
            int(self.hour.get()),
            int(self.minute.get()),
            int(self.second.get()),
            tzinfo=timezone.utc,
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.callback(value)
        self.destroy()


class DateTimeField(ttk.Frame):
    """Editable/pasteable ISO-8601 field with a calendar selector."""

    def __init__(self, parent: tk.Widget, variable: tk.StringVar, title: str) -> None:
        super().__init__(parent)
        self.variable = variable
        self.title = title
        self.entry = ttk.Entry(self, textvariable=variable)
        self.entry.pack(side="left", fill="x", expand=True)
        ttk.Button(self, text="Select…", command=self._select).pack(side="left", padx=(6, 0))
        ttk.Button(self, text="Clear", command=lambda: variable.set("")).pack(side="left", padx=(4, 0))

    def _select(self) -> None:
        CalendarDialog(self, self.variable.get(), self.variable.set, self.title)


class DateRangePanel(ttk.LabelFrame):
    def __init__(self, parent: tk.Widget, title: str = "UTC date range") -> None:
        super().__init__(parent, text=title, padding=8)
        self.start = tk.StringVar()
        self.end = tk.StringVar()
        ttk.Label(self, text="Start (inclusive)").grid(row=0, column=0, sticky="w", pady=3)
        DateTimeField(self, self.start, "Select start date/time (UTC)").grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=3)
        ttk.Label(self, text="End (exclusive)").grid(row=1, column=0, sticky="w", pady=3)
        DateTimeField(self, self.end, "Select end date/time (UTC)").grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=3)
        ttk.Label(
            self,
            text="Paste ISO 8601 values directly, or use Select… for a calendar and time dropdowns.",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.columnconfigure(1, weight=1)

    def values(self, *, required: bool = True) -> tuple[str | None, str | None]:
        return validate_range(self.start.get(), self.end.get(), required=required)


class ToggleSwitch(tk.Canvas):
    """Small cross-platform slide toggle with green-on and gray-off states."""

    def __init__(self, parent: tk.Widget, variable: tk.BooleanVar, command: Callable[[], None] | None = None) -> None:
        super().__init__(parent, width=46, height=24, highlightthickness=0, bd=0, cursor="hand2")
        self.variable = variable
        self.command = command
        self.bind("<Button-1>", self._toggle)
        self.variable.trace_add("write", lambda *_args: self._draw())
        self._draw()

    def _toggle(self, _event=None) -> None:
        self.variable.set(not self.variable.get())
        if self.command:
            self.command()

    def _draw(self) -> None:
        self.delete("all")
        on = bool(self.variable.get())
        background = "#9BE3A2" if on else "#C8C8C8"
        knob_x = 34 if on else 12
        self.create_oval(2, 2, 24, 22, fill=background, outline=background)
        self.create_oval(22, 2, 44, 22, fill=background, outline=background)
        self.create_rectangle(13, 2, 33, 22, fill=background, outline=background)
        self.create_oval(knob_x - 9, 3, knob_x + 9, 21, fill="white", outline="#888888")


class HoverToolTip:
    """Concise hover help that always advertises the clickable detail view."""

    def __init__(self, widget: tk.Widget, text: str) -> None:
        self.widget = widget
        self.text = text.rstrip() + "\n\nClick for more information."
        self.tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<Button-1>", lambda _event: self.hide(), add="+")

    def show(self, _event=None) -> None:
        if self.tip is not None:
            return
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.attributes("-topmost", True)
        x = self.widget.winfo_rootx() + self.widget.winfo_width() + 8
        y = self.widget.winfo_rooty() + 4
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self.tip,
            text=self.text,
            justify="left",
            wraplength=420,
            background="#fffbe8",
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=6,
        ).pack()

    def hide(self, _event=None) -> None:
        if self.tip is not None:
            self.tip.destroy()
            self.tip = None


class FactorInfoDialog(tk.Toplevel):
    """Scrollable, detailed factor explanation shared by every help button."""

    def __init__(self, parent: tk.Widget, metadata: dict[str, Any]) -> None:
        super().__init__(parent)
        self.title(metadata["label"])
        self.geometry("760x640")
        self.minsize(620, 480)
        self.transient(parent.winfo_toplevel())

        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text=metadata["label"], font=("TkDefaultFont", 14, "bold"), wraplength=700).pack(anchor="w")
        ttk.Label(
            outer,
            text=(
                f"{TOP_CATEGORY_LABELS.get(metadata['top_category'], metadata['top_category'])}  •  "
                f"{metadata['subcategory']}  •  Computational load: {metadata['load']}"
            ),
            font=("TkDefaultFont", 9, "bold"),
        ).pack(anchor="w", pady=(4, 8))

        canvas = tk.Canvas(outer, highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))

        def section(title: str, text: str) -> None:
            if not text:
                return
            ttk.Label(body, text=title, font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(10, 2))
            ttk.Label(body, text=text, justify="left", wraplength=690).pack(anchor="w")

        section("What it checks", metadata["description"])
        if metadata.get("suspicious_examples"):
            section("Potentially suspicious example(s)", "\n\n".join(f"• {item}" for item in metadata["suspicious_examples"]))
        if metadata.get("legitimate_examples"):
            section("Potentially legitimate / nonmatching example(s)", "\n\n".join(f"• {item}" for item in metadata["legitimate_examples"]))
        section(
            "How results are scored",
            "YES and NO are converted to points using the selected effect mode. UNKNOWN, NOT_APPLICABLE, and ERROR contribute zero points. No email is omitted from the Phish Hunt report.",
        )
        if metadata.get("false_positive_notes"):
            section("False-positive and interpretation notes", metadata["false_positive_notes"])
        if metadata.get("prerequisites"):
            section("Prerequisite data", "\n".join(f"• {item}" for item in metadata["prerequisites"]))
        parameters = metadata.get("parameters") or []
        if parameters:
            section("User-configurable values", "\n".join(f"• {item['label']}" for item in parameters))
        availability = (
            "Evaluator implemented in this release."
            if metadata.get("implemented")
            else "Evaluator unavailable for this legacy or unsupported factor. If enabled through an older configuration, it is recorded as UNKNOWN and contributes zero points."
        )
        section("Current release availability", availability)
        section("Computational load", _load_explanation(metadata["load"]))
        section(
            "Security posture",
            "Threadsaw uses only case data already stored locally. It never follows or retrieves URLs, resolves or connects to IP addresses, or opens/executes attachments while evaluating this factor.",
        )
        ttk.Button(outer, text="Close", command=self.destroy).pack(anchor="e", pady=(8, 0))
        self.bind("<Escape>", lambda _event: self.destroy())


def _load_explanation(load: str) -> str:
    return {
        "Light": "Simple indexed message lookup or local string comparison; no broad historical search.",
        "Moderate": "Reads related URL, recipient, authentication, HTML, or attachment rows for each selected message.",
        "Heavy": "Searches historical records across the complete case database; runtime grows with total case size, not just the hunt scope.",
        "Extreme": "Reserved for broad or repeated cross-table correlation with especially high cost. No current catalog factor is labeled Extreme solely for sounding complex.",
    }.get(load, load)


class CollapsibleSection(ttk.Frame):
    """A compact disclosure section used for factor subcategories."""

    def __init__(self, parent: tk.Widget, title: str, *, initially_open: bool = False) -> None:
        super().__init__(parent)
        self.title = title
        self.open = tk.BooleanVar(value=initially_open)
        self.count_text = ""
        self.header_text = tk.StringVar()
        self.header = ttk.Button(self, textvariable=self.header_text, command=self.toggle, style="Section.TButton")
        self.header.pack(fill="x")
        self.body = ttk.Frame(self, padding=(10, 4, 4, 8))
        self._refresh_header()
        if initially_open:
            self.body.pack(fill="x")

    def _refresh_header(self) -> None:
        arrow = "▼" if self.open.get() else "▶"
        suffix = f"  {self.count_text}" if self.count_text else ""
        self.header_text.set(f"{arrow} {self.title}{suffix}")

    def toggle(self) -> None:
        self.open.set(not self.open.get())
        if self.open.get():
            self.body.pack(fill="x")
        else:
            self.body.pack_forget()
        self._refresh_header()

    def set_open(self, value: bool) -> None:
        if bool(value) != self.open.get():
            self.toggle()

    def set_count(self, visible: int, total: int, enabled: int) -> None:
        self.count_text = f"({enabled} enabled • {visible}/{total} shown)"
        self._refresh_header()


class FactorRow(ttk.Frame):
    """One configurable factor row driven entirely by catalog metadata."""

    LOAD_COLORS = {"Light": "#d9f2d9", "Moderate": "#dbeafe", "Heavy": "#ffe2b8", "Extreme": "#ffd0d0"}

    def __init__(self, parent: tk.Widget, metadata: dict[str, Any], on_change: Callable[[], None]) -> None:
        super().__init__(parent, padding=(3, 5))
        self.metadata = metadata
        self.on_change = on_change
        self.enabled = tk.BooleanVar(value=False)
        self.weight = tk.StringVar(value="0")
        self.effect = tk.StringVar(value=PHISH_HUNT_EFFECT_OPTIONS[0])
        self.parameter_vars: dict[str, tk.Variable] = {}

        ToggleSwitch(self, self.enabled, self._changed).grid(row=0, column=0, rowspan=2, sticky="nw", padx=(0, 6))
        ttk.Label(self, text=metadata["label"], font=("TkDefaultFont", 9, "bold"), wraplength=330).grid(row=0, column=1, sticky="nw")
        help_label = tk.Label(self, text="?", foreground="#1f5ca8", cursor="hand2", font=("TkDefaultFont", 10, "bold underline"))
        help_label.grid(row=0, column=2, sticky="n", padx=(5, 8))
        HoverToolTip(help_label, metadata["description"])
        help_label.bind("<Button-1>", lambda _event: FactorInfoDialog(self, metadata), add="+")

        ttk.Entry(self, textvariable=self.weight, width=9).grid(row=0, column=3, sticky="nw", padx=(0, 8))
        effect_combo = ttk.Combobox(self, textvariable=self.effect, values=PHISH_HUNT_EFFECT_OPTIONS, state="readonly", width=37)
        effect_combo.grid(row=0, column=4, sticky="nw", padx=(0, 8))
        effect_combo.bind("<<ComboboxSelected>>", lambda _event: self._changed())
        self.weight.trace_add("write", lambda *_args: self._changed())

        badge = tk.Label(
            self,
            text=metadata["load"],
            background=self.LOAD_COLORS.get(metadata["load"], "#eeeeee"),
            relief="groove",
            padx=6,
            pady=2,
        )
        badge.grid(row=0, column=5, sticky="n", padx=(0, 8))
        HoverToolTip(badge, _load_explanation(metadata["load"]))
        badge.bind("<Button-1>", lambda _event: FactorInfoDialog(self, metadata), add="+")

        availability = "Available" if metadata.get("implemented") else "Evaluator pending"
        color = "#2d6a2d" if metadata.get("implemented") else "#8a5a00"
        status = tk.Label(self, text=availability, foreground=color, cursor="hand2")
        status.grid(row=0, column=6, sticky="nw")
        HoverToolTip(status, (
            "This evaluator is implemented in the current release."
            if metadata.get("implemented")
            else "This factor is fully documented and configurable, but its evaluator is pending. Enabled pending factors return UNKNOWN and zero points."
        ))
        status.bind("<Button-1>", lambda _event: FactorInfoDialog(self, metadata), add="+")

        if metadata.get("parameters"):
            parameter_frame = ttk.Frame(self)
            parameter_frame.grid(row=1, column=1, columnspan=6, sticky="ew", pady=(5, 0))
            for index, parameter in enumerate(metadata["parameters"]):
                ttk.Label(parameter_frame, text=parameter["label"]).grid(row=index, column=0, sticky="w", pady=2)
                kind = parameter.get("kind", "text")
                default = parameter.get("default", "")
                var: tk.Variable
                if kind == "choice":
                    var = tk.StringVar(value=str(default or (parameter.get("choices") or [""])[0]))
                    control = ttk.Combobox(parameter_frame, textvariable=var, values=parameter.get("choices", []), state="readonly", width=28)
                    control.bind("<<ComboboxSelected>>", lambda _event: self._changed())
                elif kind == "integer":
                    var = tk.StringVar(value=str(default))
                    control = ttk.Entry(parameter_frame, textvariable=var, width=18)
                    var.trace_add("write", lambda *_args: self._changed())
                elif kind == "multiline":
                    var = tk.StringVar(value=str(default))
                    control = ttk.Entry(parameter_frame, textvariable=var)
                    var.trace_add("write", lambda *_args: self._changed())
                else:
                    var = tk.StringVar(value=str(default))
                    control = ttk.Entry(parameter_frame, textvariable=var)
                    var.trace_add("write", lambda *_args: self._changed())
                self.parameter_vars[parameter["name"]] = var
                control.grid(row=index, column=1, sticky="ew", padx=(8, 0), pady=2)
            parameter_frame.columnconfigure(1, weight=1)
        self.columnconfigure(1, weight=1)

    def _changed(self) -> None:
        self.on_change()

    def config(self) -> dict[str, Any]:
        try:
            weight = int(self.weight.get().strip())
        except ValueError as exc:
            raise ValueError(f"{self.metadata['label']}: weight must be an integer.") from exc
        if weight < 0:
            raise ValueError(f"{self.metadata['label']}: weight must be zero or greater.")
        effect_mode = PHISH_HUNT_EFFECT_VALUES.get(self.effect.get())
        if not effect_mode:
            raise ValueError(f"{self.metadata['label']}: choose a valid effect.")
        parameters: dict[str, Any] = {}
        for parameter in self.metadata.get("parameters", []):
            value = self.parameter_vars[parameter["name"]].get()
            if parameter.get("kind") == "integer":
                try:
                    parsed = int(str(value).strip())
                except ValueError as exc:
                    raise ValueError(f"{self.metadata['label']}: {parameter['label']} must be an integer.") from exc
                minimum = parameter.get("minimum")
                if minimum is not None and parsed < minimum:
                    raise ValueError(f"{self.metadata['label']}: {parameter['label']} must be at least {minimum}.")
                value = parsed
            parameters[parameter["name"]] = value
        return {
            "factor_id": self.metadata["factor_id"],
            "enabled": bool(self.enabled.get()),
            "weight": weight,
            "effect_mode": effect_mode,
            "parameters": parameters,
        }

    def apply(self, item: dict[str, Any] | None) -> None:
        item = item or {}
        self.enabled.set(bool(item.get("enabled", False)))
        self.weight.set(str(item.get("weight", 0)))
        mode = str(item.get("effect_mode") or "risk_when_yes")
        display = next((label for label, value in PHISH_HUNT_EFFECT_VALUES.items() if value == mode), PHISH_HUNT_EFFECT_OPTIONS[0])
        self.effect.set(display)
        supplied = item.get("parameters") if isinstance(item.get("parameters"), dict) else {}
        for parameter in self.metadata.get("parameters", []):
            self.parameter_vars[parameter["name"]].set(supplied.get(parameter["name"], parameter.get("default", "")))

    def matches(self, search: str, show: str, load: str) -> bool:
        haystack = " ".join((self.metadata["label"], self.metadata["description"], self.metadata["subcategory"])).lower()
        if search and search not in haystack:
            return False
        if show == "Enabled" and not self.enabled.get():
            return False
        if show == "Disabled" and self.enabled.get():
            return False
        if show == "Unavailable" and self.metadata.get("implemented"):
            return False
        if load != "All" and self.metadata["load"] != load:
            return False
        return True


class ScrollableTab(ttk.Frame):
    """Notebook page with vertical scrolling for smaller displays.

    The visible canvas always matches the notebook width, while the inner
    ``content`` frame can grow vertically. Mouse-wheel bindings are active
    only while the pointer is over the page so normal scrolling elsewhere in
    the launcher is unaffected.
    """

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.content = ttk.Frame(self.canvas, padding=12)
        self._window_id = self.canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.content.bind("<Configure>", self._update_scroll_region)
        self.canvas.bind("<Configure>", self._resize_content)
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.content.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)
        self.content.bind("<Leave>", self._unbind_mousewheel)

    def _update_scroll_region(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_content(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self._window_id, width=event.width)

    def _bind_mousewheel(self, _event=None) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_linux_scroll_up)
        self.canvas.bind_all("<Button-5>", self._on_linux_scroll_down)

    def _unbind_mousewheel(self, _event=None) -> None:
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event: tk.Event) -> None:
        delta = getattr(event, "delta", 0)
        if delta:
            units = int(-delta / 120)
            if units == 0:
                units = -1 if delta > 0 else 1
            self.canvas.yview_scroll(units, "units")

    def _on_linux_scroll_up(self, _event=None) -> None:
        self.canvas.yview_scroll(-1, "units")

    def _on_linux_scroll_down(self, _event=None) -> None:
        self.canvas.yview_scroll(1, "units")


class SelectorPanel(ttk.LabelFrame):
    """Message-selection controls shared by reports and export modules."""

    def __init__(
        self,
        parent: tk.Widget,
        *,
        default: str = "All messages",
        scope_provider: Callable[[], list[str]] | None = None,
        allow_phish_hunt: bool = False,
        hunt_report_provider: Callable[[], list[str]] | None = None,
    ) -> None:
        super().__init__(parent, text="Message selection", padding=8)
        options = SELECTOR_OPTIONS + ((PHISH_HUNT_REPORT_SELECTOR,) if allow_phish_hunt else ())
        self.kind = tk.StringVar(value=default)
        self.sha256 = tk.StringVar()
        self.sha256_csv = tk.StringVar()
        self.scope = tk.StringVar()
        self.hunt_report = tk.StringVar()
        self.min_score = tk.StringVar(value="50")
        self.scope_provider = scope_provider
        self.hunt_report_provider = hunt_report_provider
        self.allow_phish_hunt = allow_phish_hunt

        ttk.Label(self, text="Select by").grid(row=0, column=0, sticky="w")
        selector = ttk.Combobox(self, textvariable=self.kind, values=options, state="readonly", width=30)
        selector.grid(row=0, column=1, sticky="w", padx=(8, 0))
        selector.bind("<<ComboboxSelected>>", lambda _event: self._show_active())

        self.dynamic = ttk.Frame(self)
        self.dynamic.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.dynamic.columnconfigure(1, weight=1)

        self.range_panel = DateRangePanel(self.dynamic)
        self.sha_frame = ttk.Frame(self.dynamic)
        ttk.Label(self.sha_frame, text="Message SHA-256").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.sha_frame, textvariable=self.sha256).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.sha_frame.columnconfigure(1, weight=1)

        self.csv_frame = ttk.Frame(self.dynamic)
        ttk.Label(self.csv_frame, text="SHA-256 CSV").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.csv_frame, textvariable=self.sha256_csv).grid(row=0, column=1, sticky="ew", padx=(8, 6))
        ttk.Button(self.csv_frame, text="Browse", command=self._pick_csv).grid(row=0, column=2)
        self.csv_frame.columnconfigure(1, weight=1)

        self.scope_frame = ttk.Frame(self.dynamic)
        ttk.Label(self.scope_frame, text="Scope name").grid(row=0, column=0, sticky="w")
        self.scope_combo = ttk.Combobox(self.scope_frame, textvariable=self.scope, state="readonly")
        self.scope_combo.grid(row=0, column=1, sticky="ew", padx=(8, 6))
        ttk.Button(self.scope_frame, text="Refresh", command=self.refresh_scopes).grid(row=0, column=2)
        self.scope_frame.columnconfigure(1, weight=1)

        self.hunt_frame = ttk.Frame(self.dynamic)
        ttk.Label(
            self.hunt_frame,
            text=(
                "You MUST run phish_hunt first and select its phish_hunt.csv report. "
                "The report supplies message hashes and scores; URL/attachment data is retrieved from SQLite."
            ),
            wraplength=880,
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 6))
        ttk.Label(self.hunt_frame, text="Phish Hunt report").grid(row=1, column=0, sticky="w")
        self.hunt_combo = ttk.Combobox(self.hunt_frame, textvariable=self.hunt_report, state="normal")
        self.hunt_combo.grid(row=1, column=1, sticky="ew", padx=(8, 6))
        ttk.Button(self.hunt_frame, text="Browse", command=self._pick_hunt_report).grid(row=1, column=2)
        ttk.Button(self.hunt_frame, text="Refresh", command=self.refresh_hunt_reports).grid(row=1, column=3, padx=(6, 0))
        ttk.Label(self.hunt_frame, text="Minimum score (≥)").grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(self.hunt_frame, textvariable=self.min_score, width=14).grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(6, 0))
        ttk.Label(self.hunt_frame, text="Scores are uncapped integers; negative thresholds are allowed.").grid(
            row=2, column=1, columnspan=3, sticky="w", padx=(130, 0), pady=(6, 0)
        )
        self.hunt_frame.columnconfigure(1, weight=1)

        self.columnconfigure(1, weight=1)
        self._show_active()

    def _pick_csv(self) -> None:
        value = filedialog.askopenfilename(
            title="Select SHA-256 CSV",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if value:
            self.sha256_csv.set(value)

    def _pick_hunt_report(self) -> None:
        value = filedialog.askopenfilename(
            title="Select Threadsaw Phish Hunt report",
            filetypes=(("Phish Hunt CSV", "phish_hunt.csv"), ("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if value:
            self.hunt_report.set(value)

    def _show_active(self) -> None:
        for child in (self.range_panel, self.sha_frame, self.csv_frame, self.scope_frame, self.hunt_frame):
            child.grid_forget()
        kind = self.kind.get()
        if kind == "Date range":
            self.range_panel.grid(row=0, column=0, columnspan=3, sticky="ew")
        elif kind == "One message SHA-256":
            self.sha_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
        elif kind == "SHA-256 CSV":
            self.csv_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
        elif kind == "Named scope":
            self.refresh_scopes()
            self.scope_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
        elif kind == PHISH_HUNT_REPORT_SELECTOR and self.allow_phish_hunt:
            self.refresh_hunt_reports()
            self.hunt_frame.grid(row=0, column=0, columnspan=3, sticky="ew")

    def set_scopes(self, names: list[str]) -> None:
        self.scope_combo.configure(values=names)
        if self.scope.get() not in names:
            self.scope.set(names[0] if names else "")

    def refresh_scopes(self) -> None:
        names = self.scope_provider() if self.scope_provider else []
        self.set_scopes(names)

    def set_hunt_reports(self, paths: list[str]) -> None:
        self.hunt_combo.configure(values=paths)
        current = self.hunt_report.get().strip()
        if not current and paths:
            self.hunt_report.set(paths[0])

    def refresh_hunt_reports(self) -> None:
        paths = self.hunt_report_provider() if self.hunt_report_provider else []
        self.set_hunt_reports(paths)

    def preview_arguments(self) -> tuple[list[str], list[tuple[str, str]]]:
        """Return current selector arguments without validating or touching evidence."""
        kind = self.kind.get()
        if kind == "All messages":
            return ["--all"], []
        if kind == "Date range":
            return ["--start", self.range_panel.start.get().strip() or "START_UTC",
                    "--end", self.range_panel.end.get().strip() or "END_UTC"], []
        if kind == "One message SHA-256":
            return ["--sha256", self.sha256.get().strip() or "MESSAGE_SHA256"], []
        if kind == "SHA-256 CSV":
            host = self.sha256_csv.get().strip() or "SHA256_CSV"
            return ["--sha256-csv", "/selector.csv"], [(host, "/selector.csv")]
        if kind == "Named scope":
            return ["--scope", self.scope.get().strip() or "SCOPE_NAME"], []
        if kind == PHISH_HUNT_REPORT_SELECTOR and self.allow_phish_hunt:
            host = self.hunt_report.get().strip() or "PHISH_HUNT_REPORT.csv"
            threshold = self.min_score.get().strip() or "50"
            return ["--phish-hunt-report", "/phish_hunt_report.csv", "--min-score", threshold], [
                (host, "/phish_hunt_report.csv")
            ]
        return [], []

    def arguments(self) -> tuple[list[str], list[tuple[str, str]]]:
        kind = self.kind.get()
        if kind == "All messages":
            return ["--all"], []
        if kind == "Date range":
            start, end = self.range_panel.values(required=True)
            return ["--start", str(start), "--end", str(end)], []
        if kind == "One message SHA-256":
            value = self.sha256.get().strip().lower()
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("Enter a 64-character hexadecimal message SHA-256 value.")
            return ["--sha256", value], []
        if kind == "SHA-256 CSV":
            value = self.sha256_csv.get().strip()
            if not value:
                raise ValueError("Select a SHA-256 CSV file.")
            if not Path(value).is_file():
                raise ValueError("The selected SHA-256 CSV file does not exist.")
            return ["--sha256-csv", "/selector.csv"], [(value, "/selector.csv")]
        if kind == "Named scope":
            value = self.scope.get().strip()
            if not value:
                raise ValueError("Select a named scope. Use Refresh after creating a new scope.")
            return ["--scope", value], []
        if kind == PHISH_HUNT_REPORT_SELECTOR and self.allow_phish_hunt:
            report = self.hunt_report.get().strip()
            if not report:
                raise ValueError("Run Phish Hunt first, then select its phish_hunt.csv report.")
            if not Path(report).is_file():
                raise ValueError("The selected Phish Hunt report does not exist.")
            try:
                threshold = int(self.min_score.get().strip())
            except ValueError as exc:
                raise ValueError("The Phish Hunt minimum score must be an integer.") from exc
            return ["--phish-hunt-report", "/phish_hunt_report.csv", "--min-score", str(threshold)], [
                (report, "/phish_hunt_report.csv")
            ]
        raise ValueError("Choose a message selector.")


class ThreadsawLauncher(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(DEFAULT_GEOMETRY)
        self.minsize(860, 640)
        self.process: subprocess.Popen[str] | None = None
        self.container_name: str | None = None
        self.lines: queue.Queue[str] = queue.Queue()
        self.action_buttons: list[ttk.Button] = []
        self.tabs: dict[str, ttk.Frame] = {}
        self.preview_action = "run_pipeline"
        self._last_preview = ""
        self.operation_active = False
        self.operation_name = ""
        self.operation_stage = "processing"

        self.project_dir = tk.StringVar(value=str(Path.cwd()))
        self.input_dir = tk.StringVar()
        self.case_dir = tk.StringVar()
        self.organization_domains = tk.StringVar()
        self.workers = tk.StringVar(value="4")
        self.recursive = tk.BooleanVar(value=True)
        self.include_deleted = tk.BooleanVar(value=False)
        self.large_case_mode = tk.BooleanVar(value=False)
        self.allow_low_disk = tk.BooleanVar(value=False)
        self.quiet = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready")

        self._configure_styles()
        self._build_branding()
        self._build_environment()
        self._build_notebook()
        self._build_console()
        self.after(100, self._drain)
        self.after(200, self._preview_loop)
        self.after(HEARTBEAT_INTERVAL_MS, self._heartbeat)
        self.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.configure("DashboardPrimary.TButton", font=("TkDefaultFont", 11, "bold"), padding=(16, 11))
        style.configure("Dashboard.TButton", font=("TkDefaultFont", 10, "bold"), padding=(14, 9))
        style.configure("Run.TButton", font=("TkDefaultFont", 9, "bold"), padding=(12, 7))
        style.configure("Header.TButton", font=("TkDefaultFont", 9, "bold"), padding=(10, 6))
        style.configure("Section.TButton", font=("TkDefaultFont", 10, "bold"), padding=(8, 5), anchor="w")
        style.configure("Step.TLabelframe.Label", font=("TkDefaultFont", 11, "bold"))
        style.configure("Threadsaw.TNotebook", tabmargins=(2, 5, 2, 0))
        style.configure(
            "Threadsaw.TNotebook.Tab",
            font=("TkDefaultFont", 11, "bold"),
            padding=(13, 8),
        )

    def _build_branding(self) -> None:
        banner = ttk.Frame(self, padding=(12, 10, 12, 0))
        banner.pack(fill="x")
        branding = ttk.Frame(banner)
        branding.pack(side="left", fill="x", expand=True)
        ttk.Label(branding, text="THREADSAW 1.3.0", font=("TkDefaultFont", 16, "bold")).pack(anchor="w")
        ttk.Label(branding, text=MOTTO, font=("TkDefaultFont", 10, "italic")).pack(anchor="w", pady=(2, 0))
        self._action_button(
            banner,
            "Diagnostics",
            self.run_doctor,
            style="Header.TButton",
        ).pack(side="right", anchor="ne")

    def _build_environment(self) -> None:
        frame = ttk.LabelFrame(self, text="Environment", padding=10)
        frame.pack(fill="x", padx=12, pady=(12, 6))
        self._path_row(frame, 0, "Project folder", self.project_dir, self._pick_project)
        self._path_row(frame, 1, "Input/evidence folder", self.input_dir, self._pick_input)
        self._path_row(frame, 2, "Case/output folder", self.case_dir, self._pick_case)

        ttk.Label(frame, text="Organization domains (optional)").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(frame, textvariable=self.organization_domains).grid(row=3, column=1, sticky="ew", padx=6, pady=4)
        ttk.Label(frame, text="Comma-separated; used for direction and lookalike context").grid(row=3, column=2, sticky="w", pady=4)

        options = ttk.Frame(frame)
        options.grid(row=4, column=1, sticky="w", padx=6, pady=(5, 0))
        ttk.Label(options, text="Workers").pack(side="left")
        ttk.Spinbox(options, from_=1, to=32, textvariable=self.workers, width=6).pack(side="left", padx=(5, 16))
        ttk.Checkbutton(options, text="Recursive input discovery", variable=self.recursive).pack(side="left")
        ttk.Checkbutton(options, text="Quiet CLI output", variable=self.quiet).pack(side="left", padx=(16, 0))
        frame.columnconfigure(1, weight=1)

        note = (
            "The GUI only orchestrates Docker commands and displays progress/outcomes. It never displays case evidence, "
            "follows URLs or IP addresses, or opens/executes attachments."
        )
        ttk.Label(frame, text=note, wraplength=960).grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _build_notebook(self) -> None:
        """Build a cross-platform two-row module tab bar and content stack.

        Tk's native Notebook does not wrap tabs consistently across Windows,
        macOS, and Linux. Threadsaw therefore uses two rows of tab-style radio
        buttons so every module remains visible on smaller displays.
        """
        shell = ttk.Frame(self)
        shell.pack(fill="both", expand=True, padx=12, pady=6)

        nav = ttk.Frame(shell)
        nav.pack(fill="x", pady=(0, 5))
        self.tab_nav_rows = [ttk.Frame(nav), ttk.Frame(nav)]
        for row in self.tab_nav_rows:
            row.pack(fill="x", pady=1)
        self.tab_choice = tk.StringVar(value="Workflow")
        self.tab_nav_buttons: dict[str, tk.Radiobutton] = {}

        self.tab_content_host = ttk.Frame(shell)
        self.tab_content_host.pack(fill="both", expand=True)
        self.tab_content_host.rowconfigure(0, weight=1)
        self.tab_content_host.columnconfigure(0, weight=1)

        self._build_workflow_tab()
        self._build_pipeline_tab()
        self._build_ingest_tab()
        self._build_report_tab()
        self._build_scopes_tab()
        self._build_phish_hunt_tab()
        self._build_evaluate_email_tab()
        self._build_string_search_tab()
        self._build_qr_tab()
        self._build_urls_tab()
        self._build_attachments_tab()
        self._build_export_tab()
        self._select_tab("Workflow")

    def _new_tab(self, title: str) -> ttk.Frame:
        index = len(self.tabs)
        row_index = 0 if index < 6 else 1
        column_index = index if row_index == 0 else index - 6
        nav_row = self.tab_nav_rows[row_index]
        nav_row.columnconfigure(column_index, weight=1, uniform=f"tabs-{row_index}")
        button = tk.Radiobutton(
            nav_row,
            text=title,
            variable=self.tab_choice,
            value=title,
            indicatoron=False,
            command=self._tab_changed,
            font=("TkDefaultFont", 10, "bold"),
            relief="raised",
            borderwidth=1,
            padx=7,
            pady=5,
            selectcolor="#dbeafe",
            activebackground="#eaf2ff",
        )
        button.grid(row=0, column=column_index, sticky="ew", padx=1)
        self.tab_nav_buttons[title] = button

        page = ScrollableTab(self.tab_content_host)
        page.grid(row=0, column=0, sticky="nsew")
        page.grid_remove()
        self.tabs[title] = page
        return page.content

    def _select_tab(self, title: str) -> None:
        page = self.tabs.get(title)
        if page is None:
            return
        for candidate in self.tabs.values():
            candidate.grid_remove()
        page.grid()
        self.tab_choice.set(title)
        self._tab_changed()

    def _workflow_navigation_button(
        self,
        parent: ttk.LabelFrame,
        *,
        label: str,
        tab_title: str,
        preview_action: str,
        primary: bool = False,
    ) -> None:
        ttk.Button(
            parent,
            text=label,
            style="DashboardPrimary.TButton" if primary else "Dashboard.TButton",
            command=lambda: self._open_tab(tab_title, preview_action),
        ).pack(fill="x", pady=(7, 0))

    def _build_workflow_tab(self) -> None:
        frame = self._new_tab("Workflow")
        ttk.Label(
            frame,
            text=(
                "Use the steps below to choose what you want to do. Each button opens the corresponding "
                "configuration screen; no command runs until you press the action button on that screen."
            ),
            wraplength=980,
        ).pack(anchor="w", pady=(0, 10))

        steps = ttk.Frame(frame)
        steps.pack(fill="both", expand=True)
        steps.columnconfigure(0, weight=1, uniform="workflow")
        steps.columnconfigure(1, weight=1, uniform="workflow")

        step1 = ttk.LabelFrame(steps, text="Step 1: Data Initialization", style="Step.TLabelframe", padding=10)
        step1.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        ttk.Label(
            step1,
            text="Start with Full Pipeline for most cases, or run ingestion and report generation separately.",
            wraplength=430,
        ).pack(anchor="w")
        self._workflow_navigation_button(
            step1, label="Full Pipeline", tab_title="Full Pipeline", preview_action="run_pipeline", primary=True
        )
        self._workflow_navigation_button(
            step1, label="Ingest Data", tab_title="Ingest Data", preview_action="run_ingest"
        )
        self._workflow_navigation_button(
            step1, label="Generate Reports", tab_title="Generate Reports", preview_action="run_report"
        )

        step2 = ttk.LabelFrame(steps, text="Step 2: Deeper Analysis and Exports", style="Step.TLabelframe", padding=10)
        step2.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ttk.Label(
            step2,
            text="After data is initialized, define a reusable scope or run deeper analysis and exports.",
            wraplength=430,
        ).pack(anchor="w")
        self._workflow_navigation_button(
            step2, label="Set Scope", tab_title="Set Scope", preview_action="run_scope_create"
        )
        self._workflow_navigation_button(
            step2, label="Phish Hunt", tab_title="Phish Hunt", preview_action="run_phish_hunt"
        )
        self._workflow_navigation_button(
            step2,
            label="Evaluate Phishing Email",
            tab_title="Evaluate Phishing Email",
            preview_action="run_evaluate_email",
        )
        self._workflow_navigation_button(
            step2, label="String Search", tab_title="String Search", preview_action="run_string_search"
        )
        self._workflow_navigation_button(
            step2, label="Evaluate QRs", tab_title="Evaluate QRs", preview_action="run_qr"
        )
        self._workflow_navigation_button(
            step2, label="Get URLs", tab_title="Get URLs", preview_action="run_urls"
        )
        self._workflow_navigation_button(
            step2,
            label="Export Attachments",
            tab_title="Export Attachments",
            preview_action="run_attachments_report",
        )
        self._workflow_navigation_button(
            step2, label="Export Messages", tab_title="Export Messages", preview_action="run_export_messages"
        )

    def _open_tab(self, title: str, preview_action: str) -> None:
        if title not in self.tabs:
            return
        self._select_tab(title)
        self.preview_action = preview_action
        self._refresh_command_preview()

    def _build_pipeline_tab(self) -> None:
        frame = self._new_tab("Full Pipeline")
        ttk.Label(
            frame,
            text=("Ingest PST/EML/MSG input, extract URL strings offline, and create the core reports. "
                  "Every completed pipeline receives its own UTC-timestamped report folder."),
            wraplength=900,
        ).pack(anchor="w")
        self.pipeline_use_range = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Limit pipeline reports to a UTC date range", variable=self.pipeline_use_range, command=self._toggle_pipeline_range).pack(anchor="w", pady=(10, 4))
        self.pipeline_range = DateRangePanel(frame)
        self.pipeline_range.pack(fill="x", pady=4)
        self._set_children_state(self.pipeline_range, "disabled")
        ttk.Checkbutton(frame, text="Include recoverable deleted PST items (readpst -D)", variable=self.include_deleted).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(frame, text="Large case mode (stream reports; JSON Lines)", variable=self.large_case_mode).pack(anchor="w", pady=(4, 0))
        ttk.Checkbutton(frame, text="Allow PST processing even when disk preflight is below estimate", variable=self.allow_low_disk).pack(anchor="w", pady=(4, 0))
        self._action_button(frame, "Run full pipeline", self.run_pipeline).pack(anchor="w", pady=(12, 0))

    def _build_ingest_tab(self) -> None:
        frame = self._new_tab("Ingest Data")
        ttk.Label(
            frame,
            text="Hash, extract, parse, and index PST, EML, and optional MSG input into the selected case.",
            wraplength=900,
        ).pack(anchor="w")
        ttk.Checkbutton(frame, text="Include recoverable deleted PST items (readpst -D)", variable=self.include_deleted).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(frame, text="Allow PST processing even when disk preflight is below estimate", variable=self.allow_low_disk).pack(anchor="w", pady=(4, 0))
        self._action_button(frame, "Run ingest", self.run_ingest).pack(anchor="w", pady=(12, 0))

    def _build_report_tab(self) -> None:
        frame = self._new_tab("Generate Reports")
        self.report_selector = SelectorPanel(frame, scope_provider=self._scope_names)
        self.report_selector.pack(fill="x")
        self.report_output = tk.StringVar(value="reports/core")
        self._relative_output_row(frame, "Output folder base within case (completion timestamp appended)", self.report_output, is_file=False)
        ttk.Checkbutton(frame, text="Large case mode (stream reports; write JSON Lines)", variable=self.large_case_mode).pack(anchor="w", pady=(6, 0))
        self._action_button(frame, "Generate reports", self.run_report).pack(anchor="w", pady=(12, 0))

    def _build_phish_hunt_tab(self) -> None:
        frame = self._new_tab("Phish Hunt")
        ttk.Label(
            frame,
            text=(
                "Create an explainable, zero-centered phishing-risk score for a mandatory UTC date range or named scope. "
                "Each execution creates a new completion-timestamped report folder; scores are uncapped additive integers."
            ),
            wraplength=980,
        ).pack(anchor="w", pady=(0, 8))

        guidance = ttk.LabelFrame(frame, text="How scoring works", padding=9)
        guidance.pack(fill="x", pady=(0, 8))
        ttk.Label(
            guidance,
            text=(
                "Select factors that you think are indicative of the phishing campaign. The higher the score in the output CSV, "
                "the more likely the message is to be a phishing email; the lower the score, the less likely it is. "
                "No emails are omitted from the report—they are only scored in the output CSV. Try starting with "
                "one of the preset configurations by clicking the buttons below, then adjust the factors and weights "
                "to fit the campaign you are investigating. Hover over any ? or load badge for a short explanation, "
                "then click it for the complete factor documentation and examples."
            ),
            wraplength=950,
        ).pack(anchor="w")

        selection = ttk.LabelFrame(frame, text="Required message selection", padding=8)
        selection.pack(fill="x")
        self.phish_selection_kind = tk.StringVar(value="Date range")
        ttk.Label(selection, text="Select by").grid(row=0, column=0, sticky="w")
        kind = ttk.Combobox(
            selection,
            textvariable=self.phish_selection_kind,
            values=("Date range", "Named scope"),
            state="readonly",
            width=22,
        )
        kind.grid(row=0, column=1, sticky="w", padx=(8, 0))
        kind.bind("<<ComboboxSelected>>", lambda _event: self._phish_selection_changed())
        self.phish_selection_dynamic = ttk.Frame(selection)
        self.phish_selection_dynamic.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.phish_range = DateRangePanel(self.phish_selection_dynamic)
        self.phish_scope_frame = ttk.Frame(self.phish_selection_dynamic)
        ttk.Label(self.phish_scope_frame, text="Scope name").grid(row=0, column=0, sticky="w")
        self.phish_scope = tk.StringVar()
        self.phish_scope_combo = ttk.Combobox(self.phish_scope_frame, textvariable=self.phish_scope, state="readonly")
        self.phish_scope_combo.grid(row=0, column=1, sticky="ew", padx=(8, 6))
        ttk.Button(self.phish_scope_frame, text="Refresh", command=self._refresh_phish_scope_combo).grid(row=0, column=2)
        self.phish_scope_frame.columnconfigure(1, weight=1)
        selection.columnconfigure(1, weight=1)
        self._phish_selection_changed()

        run_settings = ttk.LabelFrame(frame, text="Run settings", padding=8)
        run_settings.pack(fill="x", pady=(8, 0))
        self.phish_run_name = tk.StringVar(value="Phish Hunt")
        ttk.Label(run_settings, text="Run name").grid(row=0, column=0, sticky="w")
        ttk.Entry(run_settings, textvariable=self.phish_run_name).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.phish_output_root = tk.StringVar(value="reports/phish_hunt")
        ttk.Label(run_settings, text="Report root within case").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(run_settings, textvariable=self.phish_output_root).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(6, 0))
        ttk.Label(
            run_settings,
            text="Threadsaw creates a unique completion-timestamped subfolder for every execution; existing hunts are never overwritten.",
            wraplength=880,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(run_settings, text="Large case mode (stream outputs; write JSON Lines)", variable=self.large_case_mode).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        run_settings.columnconfigure(1, weight=1)

        presets = ttk.LabelFrame(frame, text="Preset configurations", padding=8)
        presets.pack(fill="x", pady=(8, 0))
        ttk.Label(
            presets,
            text=(
                "Starter presets provide conservative enabled factors and weights for testing. They are heuristics, not calibrated probabilities; "
                "review and adjust them for the organization and campaign before running a hunt."
            ),
            wraplength=950,
        ).pack(anchor="w")
        preset_buttons = ttk.Frame(presets)
        preset_buttons.pack(fill="x", pady=(6, 0))
        for label in ("External phishing email hunt", "Internal phishing email hunt", "General phishing email hunt"):
            ttk.Button(preset_buttons, text=label, command=lambda value=label: self._apply_phish_preset(value)).pack(side="left", padx=(0, 6))
        ttk.Button(preset_buttons, text="Clear", command=lambda: self._apply_phish_preset("Clear")).pack(side="left")

        factors = ttk.LabelFrame(frame, text="Scoring factor catalog", padding=8)
        factors.pack(fill="x", pady=(8, 0))
        self.phish_config_name = tk.StringVar(value="Prototype default (Custom)")
        config_line = ttk.Frame(factors)
        config_line.pack(fill="x")
        ttk.Label(config_line, text="Configuration:").pack(side="left")
        ttk.Label(config_line, textvariable=self.phish_config_name, font=("TkDefaultFont", 9, "bold")).pack(side="left", padx=(6, 12))
        self.phish_catalog_summary = tk.StringVar()
        ttk.Label(config_line, textvariable=self.phish_catalog_summary).pack(side="left")

        filter_line = ttk.Frame(factors)
        filter_line.pack(fill="x", pady=(8, 6))
        self.phish_factor_search = tk.StringVar()
        self.phish_factor_show = tk.StringVar(value="All")
        self.phish_factor_load = tk.StringVar(value="All")
        ttk.Label(filter_line, text="Search factors").pack(side="left")
        ttk.Entry(filter_line, textvariable=self.phish_factor_search, width=28).pack(side="left", padx=(6, 14))
        ttk.Label(filter_line, text="Show").pack(side="left")
        ttk.Combobox(filter_line, textvariable=self.phish_factor_show, values=("All", "Enabled", "Disabled", "Unavailable"), state="readonly", width=13).pack(side="left", padx=(6, 14))
        ttk.Label(filter_line, text="Load").pack(side="left")
        ttk.Combobox(filter_line, textvariable=self.phish_factor_load, values=("All", *LOAD_LEVELS), state="readonly", width=11).pack(side="left", padx=(6, 14))
        ttk.Button(filter_line, text="Expand all", command=lambda: self._set_all_phish_sections(True)).pack(side="right", padx=(6, 0))
        ttk.Button(filter_line, text="Collapse all", command=lambda: self._set_all_phish_sections(False)).pack(side="right")

        headings = ttk.Frame(factors)
        headings.pack(fill="x", pady=(2, 2))
        for column, (text, width) in enumerate((("On", 6), ("Factor", 45), ("", 3), ("Weight", 9), ("Effect", 38), ("Load", 10), ("Availability", 16))):
            label = ttk.Label(headings, text=text, font=("TkDefaultFont", 9, "bold"), width=width, anchor="w")
            label.grid(row=0, column=column, sticky="w", padx=(0, 5))
        headings.columnconfigure(1, weight=1)

        self._applying_phish_config = False
        self.phish_factor_rows: dict[str, FactorRow] = {}
        self.phish_subcategory_sections: dict[tuple[str, str], CollapsibleSection] = {}
        self.phish_category_frames: dict[str, ttk.LabelFrame] = {}
        self.phish_category_order: list[str] = []
        self.phish_subcategory_order: dict[str, list[str]] = {}
        self.phish_catalog_host = ttk.Frame(factors)
        self.phish_catalog_host.pack(fill="x")

        for top_category in ("inherently_risky", "situational"):
            category_frame = ttk.LabelFrame(
                self.phish_catalog_host,
                text=TOP_CATEGORY_LABELS[top_category],
                padding=6,
            )
            category_frame.pack(fill="x", pady=(6, 0))
            self.phish_category_frames[top_category] = category_frame
            self.phish_category_order.append(top_category)
            subcategories: list[str] = []
            for metadata in FACTOR_CATALOG:
                if metadata["top_category"] != top_category or metadata["subcategory"] in subcategories:
                    continue
                subcategories.append(metadata["subcategory"])
            self.phish_subcategory_order[top_category] = subcategories
            for sub_index, subcategory in enumerate(subcategories):
                section = CollapsibleSection(category_frame, subcategory, initially_open=(sub_index == 0))
                section.pack(fill="x", pady=(3, 0))
                self.phish_subcategory_sections[(top_category, subcategory)] = section
                items = [item for item in FACTOR_CATALOG if item["top_category"] == top_category and item["subcategory"] == subcategory]
                for metadata in items:
                    row = FactorRow(section.body, metadata, self._phish_factor_changed)
                    row.pack(fill="x")
                    row.separator = ttk.Separator(section.body, orient="horizontal")
                    row.separator.pack(fill="x")
                    self.phish_factor_rows[metadata["factor_id"]] = row

        # Start with the General phishing starter preset. The user can apply a
        # different preset, clear it, or import a saved config.json before run.
        self._apply_phish_preset("General phishing email hunt")

        self.phish_factor_search.trace_add("write", lambda *_args: self._update_phish_factor_filter())
        self.phish_factor_show.trace_add("write", lambda *_args: self._update_phish_factor_filter())
        self.phish_factor_load.trace_add("write", lambda *_args: self._update_phish_factor_filter())
        self._update_phish_factor_filter()

        config_buttons = ttk.Frame(frame)
        config_buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(config_buttons, text="Export config.json…", command=self._save_phish_config).pack(side="left")
        ttk.Button(config_buttons, text="Import config.json…", command=self._load_phish_config).pack(side="left", padx=(8, 0))
        self._action_button(config_buttons, "List prior hunts", self.run_phish_hunt_list).pack(side="right", padx=(8, 0))
        self._action_button(config_buttons, "Run Phish Hunt", self.run_phish_hunt).pack(side="right")

    def _build_evaluate_email_tab(self) -> None:
        frame = self._new_tab("Evaluate Phishing Email")
        ttk.Label(
            frame,
            text=(
                "Evaluate one email against the complete Phish Hunt factor catalog and create a starter config.json "
                "containing the factors that returned YES. Existing case messages use full case context. A new EML/MSG "
                "uses standalone factors unless it matches an existing case message or you explicitly enable the case-history override."
            ),
            wraplength=1080,
        ).pack(anchor="w", pady=(0, 8))
        ttk.Label(
            frame,
            text=(
                "All visible Phish Hunt factors have operational evaluators in this build. Threadsaw never follows URLs, "
                "connects to IP addresses, or opens/executes attachments during this evaluation."
            ),
            wraplength=1080,
            foreground="#2d6a2d",
        ).pack(anchor="w", pady=(0, 10))

        source = ttk.LabelFrame(frame, text="Email input", padding=8)
        source.pack(fill="x")
        self.evaluate_input_kind = tk.StringVar(value="Existing case SHA-256")
        ttk.Radiobutton(
            source,
            text="Existing case message SHA-256",
            variable=self.evaluate_input_kind,
            value="Existing case SHA-256",
            command=self._toggle_evaluate_input,
        ).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(
            source,
            text="New EML or MSG file",
            variable=self.evaluate_input_kind,
            value="New EML/MSG file",
            command=self._toggle_evaluate_input,
        ).grid(row=1, column=0, sticky="w", pady=(7, 0))

        self.evaluate_sha256 = tk.StringVar()
        self.evaluate_sha_entry = ttk.Entry(source, textvariable=self.evaluate_sha256)
        self.evaluate_sha_entry.grid(row=0, column=1, columnspan=2, sticky="ew", padx=(8, 0))
        self.evaluate_file = tk.StringVar()
        self.evaluate_file_entry = ttk.Entry(source, textvariable=self.evaluate_file, state="disabled")
        self.evaluate_file_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(7, 0))
        self.evaluate_file_button = ttk.Button(source, text="Browse", command=self._pick_evaluate_file, state="disabled")
        self.evaluate_file_button.grid(row=1, column=2, padx=(8, 0), pady=(7, 0))
        source.columnconfigure(1, weight=1)

        self.evaluate_allow_history = tk.BooleanVar(value=False)
        self.evaluate_history_check = ttk.Checkbutton(
            frame,
            text=(
                "For a new file not present in this case, run case-history factors anyway. "
                "This may have little value unless the file came from the same inbox or mailbox collection."
            ),
            variable=self.evaluate_allow_history,
            state="disabled",
        )
        self.evaluate_history_check.pack(anchor="w", pady=(10, 0))
        self.evaluate_output_root = tk.StringVar(value="reports/evaluate_phishing_email")
        self._relative_output_row(
            frame,
            "Output root within case (a unique completion-timestamped folder is created)",
            self.evaluate_output_root,
            is_file=False,
        )
        self._action_button(frame, "Evaluate phishing email", self.run_evaluate_email).pack(anchor="w", pady=(12, 0))

    def _build_string_search_tab(self) -> None:
        frame = self._new_tab("String Search")
        ttk.Label(
            frame,
            text=(
                "Search selected local data sources for an exact literal string occurrence without regard to case. "
                "This is not a regular-expression, fuzzy, or semantic search."
            ),
            wraplength=1080,
        ).pack(anchor="w", pady=(0, 8))
        query_row = ttk.Frame(frame)
        query_row.pack(fill="x")
        ttk.Label(query_row, text="Search string").pack(side="left")
        self.string_search_query = tk.StringVar()
        ttk.Entry(query_row, textvariable=self.string_search_query).pack(side="left", fill="x", expand=True, padx=(8, 0))

        locations = ttk.LabelFrame(frame, text="Search locations", padding=8)
        locations.pack(fill="x", pady=(10, 0))
        self.string_search_database = tk.BooleanVar(value=True)
        self.string_search_exported = tk.BooleanVar(value=True)
        self.string_search_reports = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            locations,
            text="SQLite database — all fields",
            variable=self.string_search_database,
            command=self._toggle_string_search_database,
        ).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(
            locations,
            text="Exported message review TXT files",
            variable=self.string_search_exported,
            command=self._toggle_string_search_exported,
        ).grid(row=1, column=0, sticky="w", pady=(7, 0))
        ttk.Checkbutton(
            locations,
            text="Case reports (CSV, JSON, TXT, Markdown, and logs)",
            variable=self.string_search_reports,
        ).grid(row=2, column=0, sticky="w", pady=(7, 0))

        self.string_search_exported_dir = tk.StringVar()
        self.string_search_exported_entry = ttk.Entry(locations, textvariable=self.string_search_exported_dir)
        self.string_search_exported_entry.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=(7, 0))
        self.string_search_exported_button = ttk.Button(
            locations, text="Browse", command=self._pick_string_exported_folder
        )
        self.string_search_exported_button.grid(row=1, column=2, padx=(8, 0), pady=(7, 0))
        locations.columnconfigure(1, weight=1)
        ttk.Label(
            locations,
            text="The newest completed message-export folder is populated automatically when one can be found.",
            foreground="#555555",
        ).grid(row=3, column=1, columnspan=2, sticky="w", padx=(12, 0), pady=(3, 0))

        db_range = ttk.LabelFrame(frame, text="Optional SQLite-only date range", padding=8)
        db_range.pack(fill="x", pady=(10, 0))
        self.string_search_use_range = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            db_range,
            text=(
                "Limit message-associated SQLite rows to a UTC date range. "
                "This date range does not apply to exported message TXT files or reports."
            ),
            variable=self.string_search_use_range,
            command=self._toggle_string_search_range,
        ).pack(anchor="w")
        self.string_search_range = DateRangePanel(db_range)
        self.string_search_range.pack(fill="x", pady=(6, 0))
        self._set_children_state(self.string_search_range, "disabled")

        self.string_search_output_root = tk.StringVar(value="reports/string_search")
        self._relative_output_row(
            frame,
            "Output root within case (a unique completion-timestamped folder is created)",
            self.string_search_output_root,
            is_file=False,
        )
        self._action_button(frame, "Run string search", self.run_string_search).pack(anchor="w", pady=(12, 0))

    def _build_qr_tab(self) -> None:
        frame = self._new_tab("Evaluate QRs")
        ttk.Label(
            frame,
            text=("Decode QR codes offline from stored image attachments and bounded rendered PDF pages. "
                  "Decoded text and URLs are reported but never contacted."),
            wraplength=900,
        ).pack(anchor="w", pady=(0, 8))
        self.qr_selector = SelectorPanel(
            frame, scope_provider=self._scope_names, allow_phish_hunt=True,
            hunt_report_provider=self._phish_hunt_reports,
        )
        self.qr_selector.pack(fill="x")
        options = ttk.Frame(frame)
        options.pack(fill="x", pady=(10, 0))
        self.qr_max_pdf_pages = tk.StringVar(value="100")
        self.qr_render_dpi = tk.StringVar(value="144")
        ttk.Label(options, text="Max PDF pages per attachment").pack(side="left")
        ttk.Spinbox(options, from_=1, to=1000, textvariable=self.qr_max_pdf_pages, width=7).pack(side="left", padx=(6, 18))
        ttk.Label(options, text="Render DPI").pack(side="left")
        ttk.Spinbox(options, from_=72, to=600, textvariable=self.qr_render_dpi, width=7).pack(side="left", padx=(6, 0))
        self.qr_output_root = tk.StringVar(value="reports/qr")
        self._relative_output_row(frame, "Output root within case (completion timestamp appended)", self.qr_output_root, is_file=False)
        self._action_button(frame, "Evaluate QR codes", self.run_qr).pack(anchor="w", pady=(12, 0))

    def _build_urls_tab(self) -> None:
        frame = self._new_tab("Get URLs")
        ttk.Label(frame, text="Extract and report URL strings offline. No URL, hostname, or IP address is contacted.", wraplength=900).pack(anchor="w", pady=(0, 8))
        self.urls_selector = SelectorPanel(
            frame,
            scope_provider=self._scope_names,
            allow_phish_hunt=True,
            hunt_report_provider=self._phish_hunt_reports,
        )
        self.urls_selector.pack(fill="x")
        self.urls_output = tk.StringVar(value="reports/urls.csv")
        self._relative_output_row(frame, "Output CSV base within case (completion timestamp appended)", self.urls_output, is_file=True)
        self._action_button(frame, "Extract URL strings", self.run_urls).pack(anchor="w", pady=(12, 0))

    def _build_attachments_tab(self) -> None:
        frame = self._new_tab("Export Attachments")
        ttk.Label(
            frame,
            text=(
                "Create an attachment report by itself, or create the report and copy inert attachment bytes "
                "into an analyst-friendly export tree. Attachments are never opened or executed."
            ),
            wraplength=900,
        ).pack(anchor="w", pady=(0, 8))
        self.attach_selector = SelectorPanel(
            frame,
            scope_provider=self._scope_names,
            allow_phish_hunt=True,
            hunt_report_provider=self._phish_hunt_reports,
        )
        self.attach_selector.pack(fill="x")
        extension_row = ttk.Frame(frame)
        extension_row.pack(fill="x", pady=(10, 0))
        ttk.Label(extension_row, text="Optional filename-extension filter").pack(side="left")
        self.attach_extensions = tk.StringVar()
        ttk.Entry(extension_row, textvariable=self.attach_extensions).pack(side="left", fill="x", expand=True, padx=(8, 0))
        ttk.Label(
            frame,
            text="Enter comma-separated extensions such as pdf, docx, zip. Matching is case-insensitive and based on the stored original filename.",
            foreground="#555555",
            wraplength=1000,
        ).pack(anchor="w", pady=(3, 0))
        archive_options = ttk.Frame(frame)
        archive_options.pack(fill="x", pady=(8, 0))
        self.attach_list_zip = tk.BooleanVar(value=False)
        self.attach_zip_max_members = tk.StringVar(value="1000")
        ttk.Checkbutton(archive_options, text="List bounded ZIP member metadata (no extraction)", variable=self.attach_list_zip).pack(side="left")
        ttk.Label(archive_options, text="Max members/archive").pack(side="left", padx=(16, 4))
        ttk.Spinbox(archive_options, from_=1, to=100000, textvariable=self.attach_zip_max_members, width=8).pack(side="left")
        self.attach_output = tk.StringVar(value="reports/attachments")
        self._relative_output_row(frame, "Report folder base within case (completion timestamp appended)", self.attach_output, is_file=False)
        self.attach_copy_output = tk.StringVar(value="exports/attachments")
        self._relative_output_row(
            frame,
            "Exported attachment folder base (used by the second button; completion timestamp appended)",
            self.attach_copy_output,
            is_file=False,
        )
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        self._action_button(
            buttons,
            "Generate Attachment Report Only",
            self.run_attachments_report,
        ).pack(side="left")
        self._action_button(
            buttons,
            "Generate Report and Export Attachment Files",
            self.run_attachments_export,
        ).pack(side="left", padx=(10, 0))

    def _build_export_tab(self) -> None:
        frame = self._new_tab("Export Messages")
        ttk.Label(frame, text="Export selected EMLs with companion review TXT files, summary CSV, and manifest JSON.", wraplength=900).pack(anchor="w", pady=(0, 8))
        self.export_selector = SelectorPanel(frame, scope_provider=self._scope_names)
        self.export_selector.pack(fill="x")
        self.export_output = tk.StringVar(value="exports/message-export")
        self._relative_output_row(frame, "Output folder base within case (completion timestamp appended)", self.export_output, is_file=False)
        self._action_button(frame, "Export messages", self.run_export_messages).pack(anchor="w", pady=(12, 0))

    def _build_scopes_tab(self) -> None:
        frame = self._new_tab("Set Scope")
        create = ttk.LabelFrame(frame, text="Create fixed named scope", padding=8)
        create.pack(fill="x")
        self.scope_name = tk.StringVar()
        ttk.Label(create, text="Scope name").grid(row=0, column=0, sticky="w")
        ttk.Entry(create, textvariable=self.scope_name).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.scope_range = DateRangePanel(create)
        self.scope_range.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        create.columnconfigure(1, weight=1)
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        self._action_button(buttons, "Create scope", self.run_scope_create).pack(side="left")
        self._action_button(buttons, "List scopes", self.run_scope_list).pack(side="left", padx=(8, 0))

    def _build_console(self) -> None:
        lower = ttk.Frame(self, padding=(12, 0, 12, 12))
        lower.pack(fill="both", expand=True)
        preview = ttk.LabelFrame(lower, text="Command preview (not executed)", padding=6)
        preview.pack(fill="x", pady=(0, 6))
        self.command_preview = tk.Text(preview, wrap="word", height=3, background="#f4f4f4")
        self.command_preview.pack(fill="x")
        self.command_preview.configure(state="disabled")
        toolbar = ttk.Frame(lower)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, textvariable=self.status).pack(side="left")
        self.stop_button = ttk.Button(toolbar, text="Stop current operation", command=self.stop, state="disabled")
        self.stop_button.pack(side="right")
        ttk.Button(toolbar, text="Clear progress", command=lambda: self.output.delete("1.0", "end")).pack(side="right", padx=(0, 8))
        self.output = tk.Text(lower, wrap="none", height=11)
        self.output.pack(fill="both", expand=True, pady=(6, 0))

    def _set_preview_action(self, action_name: str) -> None:
        self.preview_action = action_name
        self._refresh_command_preview()

    def _tab_changed(self, _event=None) -> None:
        defaults = {
            "Workflow": "run_pipeline",
            "Full Pipeline": "run_pipeline",
            "Ingest Data": "run_ingest",
            "Generate Reports": "run_report",
            "Set Scope": "run_scope_create",
            "Phish Hunt": "run_phish_hunt",
            "Evaluate Phishing Email": "run_evaluate_email",
            "String Search": "run_string_search",
            "Evaluate QRs": "run_qr",
            "Get URLs": "run_urls",
            "Export Attachments": "run_attachments_report",
            "Export Messages": "run_export_messages",
        }
        title = self.tab_choice.get() if hasattr(self, "tab_choice") else "Workflow"
        page = self.tabs.get(title)
        if page is not None and not page.winfo_ismapped():
            for candidate in self.tabs.values():
                candidate.grid_remove()
            page.grid()
        self.preview_action = defaults.get(title, "run_pipeline")
        self._refresh_command_preview()

    @staticmethod
    def _preview_output_arg(value: str, default: str) -> str:
        relative = (value or default).strip().replace("\\", "/").lstrip("/")
        return f"/case/{relative or default}"

    def _preview_selector(self, selector: SelectorPanel) -> tuple[list[str], list[tuple[str, str]]]:
        return selector.preview_arguments()

    def _organization_domain_args(self) -> list[str]:
        values = [item.strip() for item in re.split(r"[,;\s]+", self.organization_domains.get()) if item.strip()]
        output: list[str] = []
        for value in values:
            output.extend(["--organization-domain", value])
        return output

    def _preview_cli(self) -> tuple[list[str], bool, list[tuple[str, str]]]:
        action = self.preview_action
        quiet = ["--quiet"] if self.quiet.get() else []
        workers = self.workers.get().strip() or "4"
        mounts: list[tuple[str, str]] = []
        needs_input = False

        if action == "run_pipeline":
            args = ["run", "--input", "/input", "--case", "/case", "--workers", workers]
            args += self._organization_domain_args()
            if self.pipeline_use_range.get():
                args += ["--start", self.pipeline_range.start.get().strip() or "START_UTC",
                         "--end", self.pipeline_range.end.get().strip() or "END_UTC"]
            if self.include_deleted.get():
                args.append("--include-deleted")
            if self.allow_low_disk.get():
                args.append("--allow-low-disk")
            if self.large_case_mode.get():
                args.append("--large-case")
            needs_input = True
        elif action == "run_ingest":
            args = ["ingest", "--input", "/input", "--case", "/case", "--workers", workers]
            args += self._organization_domain_args()
            if not self.recursive.get():
                args.append("--no-recursive")
            if self.include_deleted.get():
                args.append("--include-deleted")
            if self.allow_low_disk.get():
                args.append("--allow-low-disk")
            needs_input = True
        elif action == "run_report":
            selection, mounts = self._preview_selector(self.report_selector)
            args = ["report", "--case", "/case", "--output",
                    self._preview_output_arg(self.report_output.get(), "reports/core"), *selection]
            if self.large_case_mode.get():
                args.append("--large-case")
        elif action == "run_phish_hunt_list":
            args = ["phish-hunt-list", "--case", "/case"]
        elif action == "run_phish_hunt":
            if self.phish_selection_kind.get() == "Named scope":
                selection = ["--scope", self.phish_scope.get().strip() or "SCOPE_NAME"]
            else:
                selection = [
                    "--start", self.phish_range.start.get().strip() or "START_UTC",
                    "--end", self.phish_range.end.get().strip() or "END_UTC",
                ]
            args = [
                "phish-hunt", "--case", "/case",
                "--output-root", self._preview_output_arg(self.phish_output_root.get(), "reports/phish_hunt"),
                "--config", "/case/configs/phish_hunt/gui_active.json",
                "--run-name", self.phish_run_name.get().strip() or "Prototype hunt",
                *selection,
            ]
            if self.large_case_mode.get():
                args.append("--large-case")
        elif action == "run_evaluate_email":
            args = [
                "evaluate-phishing-email", "--case", "/case",
                "--output-root", self._preview_output_arg(
                    self.evaluate_output_root.get(), "reports/evaluate_phishing_email"
                ),
            ]
            if self.evaluate_input_kind.get() == "Existing case SHA-256":
                args += ["--sha256", self.evaluate_sha256.get().strip() or "MESSAGE_SHA256"]
            else:
                selected = self.evaluate_file.get().strip() or "EMAIL_FILE.eml"
                file_name = Path(selected).name or "EMAIL_FILE.eml"
                args += ["--email-file", f"/evaluate-input/{file_name}"]
                mounts = [(str(Path(selected).parent) if selected != "EMAIL_FILE.eml" else "EMAIL_FILE_FOLDER", "/evaluate-input")]
                if self.evaluate_allow_history.get():
                    args.append("--allow-case-history")
        elif action == "run_string_search":
            args = [
                "string-search", "--case", "/case",
                "--query", self.string_search_query.get().strip() or "SEARCH_STRING",
                "--output-root", self._preview_output_arg(
                    self.string_search_output_root.get(), "reports/string_search"
                ),
            ]
            if self.string_search_database.get():
                args.append("--database")
                if self.string_search_use_range.get():
                    args += [
                        "--start", self.string_search_range.start.get().strip() or "START_UTC",
                        "--end", self.string_search_range.end.get().strip() or "END_UTC",
                    ]
            if self.string_search_exported.get():
                folder = self.string_search_exported_dir.get().strip() or "EXPORTED_MESSAGE_TEXT_FOLDER"
                case_value = self.case_dir.get().strip()
                relative = path_within(Path(folder), Path(case_value)) if case_value and folder != "EXPORTED_MESSAGE_TEXT_FOLDER" else None
                if relative is not None:
                    container_folder = "/case" if str(relative) == "." else "/case/" + relative.as_posix()
                else:
                    container_folder = "/search-exported-text"
                    mounts = [(folder, container_folder)]
                args += ["--exported-text-dir", container_folder]
            if self.string_search_reports.get():
                args.append("--reports")
        elif action == "run_qr":
            selection, mounts = self._preview_selector(self.qr_selector)
            args = [
                "qr", "--case", "/case",
                "--output-root", self._preview_output_arg(self.qr_output_root.get(), "reports/qr"),
                "--max-pdf-pages", self.qr_max_pdf_pages.get().strip() or "100",
                "--render-dpi", self.qr_render_dpi.get().strip() or "144",
                *selection,
            ]
        elif action == "run_urls":
            selection, mounts = self._preview_selector(self.urls_selector)
            args = ["urls", "--case", "/case", "--output",
                    self._preview_output_arg(self.urls_output.get(), "reports/urls.csv"), *selection]
        elif action in {"run_attachments_report", "run_attachments_export"}:
            selection, mounts = self._preview_selector(self.attach_selector)
            args = ["attachments", "--case", "/case", "--output",
                    self._preview_output_arg(self.attach_output.get(), "reports/attachments")]
            if action == "run_attachments_export":
                args += ["--copy-files", "--copy-output",
                         self._preview_output_arg(self.attach_copy_output.get(), "exports/attachments")]
            extension_value = self.attach_extensions.get().strip()
            if extension_value:
                args += ["--extension", extension_value]
            args += selection
        elif action == "run_export_messages":
            selection, mounts = self._preview_selector(self.export_selector)
            args = ["export-messages", "--case", "/case", "--output",
                    self._preview_output_arg(self.export_output.get(), "exports/message-export"), *selection]
        elif action == "run_scope_create":
            args = ["scope", "create", "--case", "/case", "--name",
                    self.scope_name.get().strip() or "SCOPE_NAME", "--start",
                    self.scope_range.start.get().strip() or "START_UTC", "--end",
                    self.scope_range.end.get().strip() or "END_UTC"]
        elif action == "run_scope_list":
            args = ["scope", "list", "--case", "/case"]
        else:
            args = ["doctor", "--case", "/case"]
        return [*quiet, *args], needs_input, mounts

    def _set_command_preview(self, command: list[str]) -> None:
        rendered = format_command(command)
        if rendered == self._last_preview:
            return
        self._last_preview = rendered
        self.command_preview.configure(state="normal")
        self.command_preview.delete("1.0", "end")
        self.command_preview.insert("1.0", rendered)
        self.command_preview.configure(state="disabled")

    def _refresh_command_preview(self) -> None:
        if not hasattr(self, "command_preview"):
            return
        try:
            cli_args, needs_input, mounts = self._preview_cli()
            case = self.case_dir.get().strip() or "CASE_OUTPUT_FOLDER"
            input_dir = (self.input_dir.get().strip() or "INPUT_FOLDER") if needs_input else None
            command = build_preview_compose_command(
                case_dir=case,
                input_dir=input_dir,
                cli_args=cli_args,
                extra_readonly_mounts=mounts,
            )
            self._set_command_preview(command)
        except Exception as exc:
            self._set_command_preview(["Complete selections to preview command:", str(exc)])

    def _preview_loop(self) -> None:
        self._refresh_command_preview()
        self.after(250, self._preview_loop)

    def _path_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, command: Callable[[], None]) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=6)
        ttk.Button(parent, text="Browse", command=command).grid(row=row, column=2)

    def _relative_output_row(self, parent: ttk.Frame, label: str, variable: tk.StringVar, *, is_file: bool) -> None:
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(10, 0))
        ttk.Label(row, text=label).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="Browse", command=lambda: self._pick_case_output(variable, is_file=is_file)).pack(side="left")

    def _action_button(
        self,
        parent: tk.Widget,
        text: str,
        command: Callable[[], None],
        *,
        style: str = "Run.TButton",
    ) -> ttk.Button:
        button = ttk.Button(parent, text=text, command=command, style=style)
        action_name = command.__name__
        button.bind("<Enter>", lambda _event, name=action_name: self._set_preview_action(name))
        button.bind("<FocusIn>", lambda _event, name=action_name: self._set_preview_action(name))
        self.action_buttons.append(button)
        return button

    def _pick_project(self) -> None:
        value = filedialog.askdirectory(title="Select the Threadsaw project folder")
        if value:
            self.project_dir.set(value)

    def _pick_input(self) -> None:
        value = filedialog.askdirectory(title="Select input/evidence folder")
        if value:
            self.input_dir.set(value)

    def _pick_case(self) -> None:
        value = filedialog.askdirectory(title="Select case/output folder")
        if value:
            self.case_dir.set(value)
            self._refresh_scope_selectors()
            self._refresh_hunt_report_selectors()
            self._populate_string_search_default()

    def _populate_string_search_default(self) -> None:
        if not hasattr(self, "string_search_exported_dir"):
            return
        discovered = discover_exported_message_text_folder(self.case_dir.get())
        if discovered:
            self.string_search_exported_dir.set(discovered)

    def _pick_string_exported_folder(self) -> None:
        initial = self.string_search_exported_dir.get().strip() or self.case_dir.get().strip() or None
        value = filedialog.askdirectory(
            title="Select folder containing exported message review TXT files",
            initialdir=initial,
        )
        if value:
            self.string_search_exported_dir.set(value)

    def _pick_evaluate_file(self) -> None:
        value = filedialog.askopenfilename(
            title="Select EML or MSG file",
            filetypes=(("Email files", "*.eml *.msg"), ("EML files", "*.eml"), ("MSG files", "*.msg"), ("All files", "*.*")),
        )
        if value:
            self.evaluate_file.set(value)

    def _toggle_evaluate_input(self) -> None:
        external = self.evaluate_input_kind.get() == "New EML/MSG file"
        self.evaluate_sha_entry.configure(state="disabled" if external else "normal")
        self.evaluate_file_entry.configure(state="normal" if external else "disabled")
        self.evaluate_file_button.configure(state="normal" if external else "disabled")
        self.evaluate_history_check.configure(state="normal" if external else "disabled")

    def _toggle_string_search_database(self) -> None:
        enabled = self.string_search_database.get()
        if not enabled:
            self.string_search_use_range.set(False)
        self._toggle_string_search_range()

    def _toggle_string_search_range(self) -> None:
        enabled = self.string_search_database.get() and self.string_search_use_range.get()
        self._set_children_state(self.string_search_range, "normal" if enabled else "disabled")

    def _toggle_string_search_exported(self) -> None:
        state = "normal" if self.string_search_exported.get() else "disabled"
        self.string_search_exported_entry.configure(state=state)
        self.string_search_exported_button.configure(state=state)

    def _pick_case_output(self, variable: tk.StringVar, *, is_file: bool) -> None:
        case = self._require_case(create=False)
        if case is None:
            return
        if is_file:
            value = filedialog.asksaveasfilename(
                title="Select output file inside the case folder",
                initialdir=case,
                initialfile=Path(variable.get()).name,
                defaultextension=".csv",
                filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            )
        else:
            value = filedialog.askdirectory(title="Select output folder inside the case folder", initialdir=case)
        if not value:
            return
        relative = path_within(Path(value), case)
        if relative is None:
            messagebox.showerror("Invalid output", "Choose an output inside the selected case/output folder.")
            return
        variable.set(relative.as_posix())

    def _toggle_pipeline_range(self) -> None:
        self._set_children_state(self.pipeline_range, "normal" if self.pipeline_use_range.get() else "disabled")

    def _set_children_state(self, widget: tk.Widget, state: str) -> None:
        for child in widget.winfo_children():
            try:
                child.configure(state=state)
            except tk.TclError:
                pass
            self._set_children_state(child, state)

    def _require_project(self) -> Path | None:
        project = Path(self.project_dir.get()).expanduser()
        if not (project / "compose.yaml").exists():
            messagebox.showerror("Invalid project folder", "compose.yaml was not found in the selected project folder.")
            return None
        return project

    def _require_case(self, *, create: bool = True) -> Path | None:
        value = self.case_dir.get().strip()
        if not value:
            messagebox.showerror("Missing information", "Select a case/output folder.")
            return None
        path = Path(value).expanduser().resolve()
        if create:
            path.mkdir(parents=True, exist_ok=True)
            return path
        if not path.is_dir() or not (path / "case.json").is_file():
            messagebox.showerror(
                "Threadsaw case not found",
                "No Threadsaw case was found in the selected output folder. "
                "Run Ingest Data or Full Pipeline first.",
            )
            return None
        return path

    def _require_input(self) -> Path | None:
        value = self.input_dir.get().strip()
        if not value:
            messagebox.showerror("Missing information", "Select an input/evidence folder.")
            return None
        path = Path(value).expanduser().resolve()
        if not path.is_dir():
            messagebox.showerror("Invalid input", "The selected input/evidence folder does not exist.")
            return None
        return path

    def _scope_names(self) -> list[str]:
        project = self.project_dir.get().strip()
        case = self.case_dir.get().strip()
        if not project or not case:
            return []
        try:
            return read_scope_names(project, case)
        except RuntimeError as exc:
            self.lines.put(f"\nScope refresh warning: {exc}\n")
            return []

    def _phish_hunt_reports(self) -> list[str]:
        return discover_phish_hunt_reports(self.case_dir.get())

    def _refresh_hunt_report_selectors(self) -> None:
        reports = self._phish_hunt_reports()
        for selector in (self.urls_selector, self.attach_selector):
            selector.set_hunt_reports(reports)

    def _refresh_phish_scope_combo(self) -> None:
        names = self._scope_names()
        self.phish_scope_combo.configure(values=names)
        if self.phish_scope.get() not in names:
            self.phish_scope.set(names[0] if names else "")

    def _phish_selection_changed(self) -> None:
        for child in (self.phish_range, self.phish_scope_frame):
            try:
                child.pack_forget()
            except tk.TclError:
                pass
        if self.phish_selection_kind.get() == "Named scope":
            self._refresh_phish_scope_combo()
            self.phish_scope_frame.pack(fill="x")
        else:
            self.phish_range.pack(fill="x")

    def _phish_mark_custom(self) -> None:
        if not getattr(self, "_applying_phish_config", False):
            self.phish_config_name.set("Custom")

    def _phish_factor_changed(self) -> None:
        self._phish_mark_custom()
        self._update_phish_factor_filter()

    def _set_all_phish_sections(self, value: bool) -> None:
        for section in self.phish_subcategory_sections.values():
            section.set_open(value)

    def _update_phish_factor_filter(self) -> None:
        if not hasattr(self, "phish_factor_rows"):
            return
        search = self.phish_factor_search.get().strip().lower()
        show = self.phish_factor_show.get()
        load = self.phish_factor_load.get()
        enabled_total = sum(1 for row in self.phish_factor_rows.values() if row.enabled.get())
        implemented_total = sum(1 for row in self.phish_factor_rows.values() if row.metadata.get("implemented"))
        heaviest = "Light"
        order = {name: index for index, name in enumerate(LOAD_LEVELS)}
        for row in self.phish_factor_rows.values():
            if row.enabled.get() and order[row.metadata["load"]] > order[heaviest]:
                heaviest = row.metadata["load"]
        self.phish_catalog_summary.set(
            f"{enabled_total} enabled • {implemented_total}/{len(self.phish_factor_rows)} evaluators currently implemented • estimated enabled load: {heaviest if enabled_total else 'None'}"
        )

        for top_category in self.phish_category_order:
            category_visible = False
            category_frame = self.phish_category_frames[top_category]
            for subcategory in self.phish_subcategory_order[top_category]:
                section = self.phish_subcategory_sections[(top_category, subcategory)]
                rows = [
                    row for row in self.phish_factor_rows.values()
                    if row.metadata["top_category"] == top_category and row.metadata["subcategory"] == subcategory
                ]
                visible_rows = [row for row in rows if row.matches(search, show, load)]
                for row in rows:
                    visible = row in visible_rows
                    if visible:
                        if not row.winfo_manager():
                            row.pack(fill="x")
                            row.separator.pack(fill="x")
                    else:
                        row.pack_forget()
                        row.separator.pack_forget()
                section.set_count(len(visible_rows), len(rows), sum(1 for row in rows if row.enabled.get()))
                if visible_rows:
                    if not section.winfo_manager():
                        section.pack(fill="x", pady=(3, 0))
                    category_visible = True
                else:
                    section.pack_forget()
            if category_visible:
                if not category_frame.winfo_manager():
                    category_frame.pack(fill="x", pady=(6, 0))
            else:
                category_frame.pack_forget()

    def _apply_phish_preset(self, name: str) -> None:
        try:
            document = preset_config("clear" if name == "Clear" else name)
        except ValueError as exc:
            messagebox.showerror("Invalid preset", str(exc))
            return
        by_id = {item["factor_id"]: item for item in document["factors"]}
        self._applying_phish_config = True
        try:
            for factor_id, row in self.phish_factor_rows.items():
                row.apply(by_id.get(factor_id))
            self.phish_config_name.set(document["name"])
        finally:
            self._applying_phish_config = False
        self._update_phish_factor_filter()

    def _current_phish_config(self) -> dict:
        factors = [self.phish_factor_rows[item["factor_id"]].config() for item in FACTOR_CATALOG]
        return phish_hunt_config_document(name=self.phish_config_name.get(), factors=factors)

    def _write_active_phish_config(self, case: Path) -> Path:
        document = self._current_phish_config()
        destination = case / "configs" / "phish_hunt" / "gui_active.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_suffix(".tmp")
        temp.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temp.replace(destination)
        return destination

    def _save_phish_config(self) -> None:
        try:
            document = self._current_phish_config()
        except ValueError as exc:
            messagebox.showerror("Invalid configuration", str(exc))
            return
        value = filedialog.asksaveasfilename(
            title="Export Phish Hunt config.json",
            defaultextension=".json",
            initialfile="phish_hunt_config.json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if value:
            Path(value).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _load_phish_config(self) -> None:
        value = filedialog.askopenfilename(
            title="Import Phish Hunt config.json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if not value:
            return
        try:
            raw = json.loads(Path(value).read_text(encoding="utf-8"))
            factors = raw.get("factors") if isinstance(raw, dict) else None
            if not isinstance(factors, list):
                raise ValueError("Configuration factors must be a list.")
            by_id = {
                str(item.get("factor_id")): item
                for item in factors
                if isinstance(item, dict) and item.get("factor_id")
            }
            self._applying_phish_config = True
            try:
                for factor_id, row in self.phish_factor_rows.items():
                    row.apply(by_id.get(factor_id))
                self.phish_config_name.set(str(raw.get("name") or "Custom"))
            finally:
                self._applying_phish_config = False
            self._update_phish_factor_filter()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            messagebox.showerror("Invalid configuration", str(exc))

    def _refresh_scope_selectors(self) -> None:
        names = self._scope_names()
        for selector in (self.report_selector, self.urls_selector, self.attach_selector, self.qr_selector, self.export_selector):
            selector.set_scopes(names)
        self.phish_scope_combo.configure(values=names)
        if self.phish_scope.get() not in names:
            self.phish_scope.set(names[0] if names else "")

    def _workers_value(self) -> str:
        try:
            value = int(self.workers.get())
        except ValueError as exc:
            raise ValueError("Workers must be an integer from 1 through 32.") from exc
        if value < 1 or value > 32:
            raise ValueError("Workers must be from 1 through 32.")
        return str(value)

    def _output_arg(self, relative: str, *, default: str) -> str:
        value = relative.strip() or default
        if Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("Output paths must be relative paths within the selected case folder.")
        return "/case/" + Path(value).as_posix().lstrip("/")

    def _run_cli(
        self,
        cli_args: list[str],
        *,
        needs_input: bool = False,
        extra_mounts: list[tuple[str, str]] | None = None,
    ) -> None:
        project = self._require_project()
        case = self._require_case(create=needs_input)
        input_path = self._require_input() if needs_input else None
        if project is None or case is None or (needs_input and input_path is None):
            return
        if needs_input and input_path is not None and input_path == case:
            messagebox.showerror(
                "Unsafe folder selection",
                "The input/evidence folder and case/output folder must be different. "
                "The input is mounted read-only and the case is writable.",
            )
            return
        name = f"threadsaw-gui-{uuid.uuid4().hex[:10]}"
        command = build_compose_command(
            case_dir=str(case),
            input_dir=str(input_path) if input_path else None,
            cli_args=(["--quiet"] if self.quiet.get() else []) + cli_args,
            extra_readonly_mounts=extra_mounts,
            container_name=name,
        )
        self._set_command_preview(command)
        self._start(command, project, name, cli_args[0])

    def run_pipeline(self) -> None:
        try:
            args = ["run", "--input", "/input", "--case", "/case", "--workers", self._workers_value()]
            args += self._organization_domain_args()
            if self.pipeline_use_range.get():
                start, end = self.pipeline_range.values(required=True)
                args += ["--start", str(start), "--end", str(end)]
            if self.include_deleted.get():
                args.append("--include-deleted")
            if self.allow_low_disk.get():
                args.append("--allow-low-disk")
            if self.large_case_mode.get():
                args.append("--large-case")
            self._run_cli(args, needs_input=True)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_ingest(self) -> None:
        try:
            args = ["ingest", "--input", "/input", "--case", "/case", "--workers", self._workers_value()]
            args += self._organization_domain_args()
            if not self.recursive.get():
                args.append("--no-recursive")
            if self.include_deleted.get():
                args.append("--include-deleted")
            if self.allow_low_disk.get():
                args.append("--allow-low-disk")
            self._run_cli(args, needs_input=True)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def _selector_command(self, base: list[str], selector: SelectorPanel) -> tuple[list[str], list[tuple[str, str]]]:
        selector_args, mounts = selector.arguments()
        return [*base, *selector_args], mounts

    def run_report(self) -> None:
        try:
            output = self._output_arg(self.report_output.get(), default="reports/core")
            args, mounts = self._selector_command(["report", "--case", "/case", "--output", output], self.report_selector)
            if self.large_case_mode.get():
                args.append("--large-case")
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_phish_hunt_list(self) -> None:
        self._run_cli(["phish-hunt-list", "--case", "/case"])

    def run_phish_hunt(self) -> None:
        try:
            case = self._require_case()
            if case is None:
                return
            output_root = self._output_arg(self.phish_output_root.get(), default="reports/phish_hunt")
            run_name = self.phish_run_name.get().strip() or "Prototype hunt"
            args = [
                "phish-hunt", "--case", "/case",
                "--output-root", output_root,
                "--config", "/case/configs/phish_hunt/gui_active.json",
                "--run-name", run_name,
            ]
            if self.phish_selection_kind.get() == "Named scope":
                scope = self.phish_scope.get().strip()
                if not scope:
                    raise ValueError("Select a named scope. Use Refresh after creating a new scope.")
                args += ["--scope", scope]
            else:
                start, end = self.phish_range.values(required=True)
                start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
                span_days = (end_dt - start_dt).total_seconds() / 86400
                if span_days > 7 and not messagebox.askyesno(
                    "Long Phish Hunt range",
                    f"This range spans {span_days:.1f} days. Phish Hunt may take a long time. Continue?",
                ):
                    return
                args += ["--start", str(start), "--end", str(end)]
            if self.large_case_mode.get():
                args.append("--large-case")
            self._write_active_phish_config(case)
            self._run_cli(args)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_evaluate_email(self) -> None:
        try:
            case = self._require_case()
            if case is None:
                return
            args = [
                "evaluate-phishing-email",
                "--case",
                "/case",
                "--output-root",
                self._output_arg(self.evaluate_output_root.get(), default="reports/evaluate_phishing_email"),
            ]
            mounts: list[tuple[str, str]] = []
            if self.evaluate_input_kind.get() == "Existing case SHA-256":
                value = self.evaluate_sha256.get().strip().lower()
                if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                    raise ValueError("Enter a valid 64-character hexadecimal message SHA-256.")
                args += ["--sha256", value]
            else:
                path = Path(self.evaluate_file.get().strip()).expanduser().resolve()
                if not path.is_file():
                    raise ValueError("Select an existing EML or MSG file.")
                if path.suffix.lower() not in {".eml", ".msg"}:
                    raise ValueError("Evaluate Phishing Email accepts only EML or MSG files.")
                relative = path_within(path, case)
                if relative is not None:
                    container_path = "/case/" + relative.as_posix()
                else:
                    container_path = f"/evaluate-input/{path.name}"
                    mounts.append((str(path.parent), "/evaluate-input"))
                args += ["--email-file", container_path]
                if self.evaluate_allow_history.get():
                    if not messagebox.askyesno(
                        "Use case history for an external email?",
                        "The selected EML/MSG may not have come from the same inbox as this case. "
                        "Historical factors may therefore produce misleading or low-value results. Continue?",
                    ):
                        return
                    args.append("--allow-case-history")
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_string_search(self) -> None:
        try:
            case = self._require_case()
            if case is None:
                return
            query = self.string_search_query.get().strip()
            if not query:
                raise ValueError("Enter a string to search for.")
            if not any((
                self.string_search_database.get(),
                self.string_search_exported.get(),
                self.string_search_reports.get(),
            )):
                raise ValueError("Select at least one search location.")
            args = [
                "string-search",
                "--case",
                "/case",
                "--query",
                query,
                "--output-root",
                self._output_arg(self.string_search_output_root.get(), default="reports/string_search"),
            ]
            mounts: list[tuple[str, str]] = []
            if self.string_search_database.get():
                args.append("--database")
                if self.string_search_use_range.get():
                    start, end = self.string_search_range.values(required=True)
                    args += ["--start", str(start), "--end", str(end)]
            if self.string_search_exported.get():
                folder = Path(self.string_search_exported_dir.get().strip()).expanduser().resolve()
                if not folder.is_dir():
                    raise ValueError("Select an existing folder containing exported message review TXT files.")
                relative = path_within(folder, case)
                if relative is not None:
                    container_folder = "/case" if str(relative) == "." else "/case/" + relative.as_posix()
                else:
                    container_folder = "/search-exported-text"
                    mounts.append((str(folder), container_folder))
                args += ["--exported-text-dir", container_folder]
            if self.string_search_reports.get():
                args.append("--reports")
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_qr(self) -> None:
        try:
            max_pages = int(self.qr_max_pdf_pages.get().strip())
            dpi = int(self.qr_render_dpi.get().strip())
            if max_pages < 1 or not 72 <= dpi <= 600:
                raise ValueError("QR settings require at least one PDF page and render DPI from 72 through 600.")
            base = [
                "qr", "--case", "/case",
                "--output-root", self._output_arg(self.qr_output_root.get(), default="reports/qr"),
                "--max-pdf-pages", str(max_pages), "--render-dpi", str(dpi),
            ]
            args, mounts = self._selector_command(base, self.qr_selector)
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_urls(self) -> None:
        try:
            output = self._output_arg(self.urls_output.get(), default="reports/urls.csv")
            args, mounts = self._selector_command(["urls", "--case", "/case", "--output", output], self.urls_selector)
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def _run_attachments(self, *, copy_files: bool) -> None:
        try:
            output = self._output_arg(self.attach_output.get(), default="reports/attachments")
            base = ["attachments", "--case", "/case", "--output", output]
            extension_value = self.attach_extensions.get().strip()
            if extension_value:
                base += ["--extension", extension_value]
            if self.attach_list_zip.get():
                try:
                    zip_max = int(self.attach_zip_max_members.get().strip())
                except ValueError as exc:
                    raise ValueError("Maximum ZIP members must be an integer.") from exc
                if zip_max < 1:
                    raise ValueError("Maximum ZIP members must be positive.")
                base += ["--list-zip-contents", "--zip-max-members", str(zip_max)]
            if copy_files:
                base.append("--copy-files")
                base += ["--copy-output", self._output_arg(self.attach_copy_output.get(), default="exports/attachments")]
            args, mounts = self._selector_command(base, self.attach_selector)
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_attachments_report(self) -> None:
        self._run_attachments(copy_files=False)

    def run_attachments_export(self) -> None:
        self._run_attachments(copy_files=True)

    def run_export_messages(self) -> None:
        try:
            output = self._output_arg(self.export_output.get(), default="exports/message-export")
            args, mounts = self._selector_command(["export-messages", "--case", "/case", "--output", output], self.export_selector)
            self._run_cli(args, extra_mounts=mounts)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_scope_create(self) -> None:
        try:
            name = self.scope_name.get().strip()
            if not name:
                raise ValueError("Enter a scope name.")
            start, end = self.scope_range.values(required=True)
            self._run_cli(["scope", "create", "--case", "/case", "--name", name, "--start", str(start), "--end", str(end)])
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def run_scope_list(self) -> None:
        self._run_cli(["scope", "list", "--case", "/case"])

    def run_doctor(self) -> None:
        self._run_cli(["doctor", "--case", "/case"])

    def _start(self, command: list[str], project: Path, container_name: str, operation_name: str) -> None:
        if self.operation_active:
            messagebox.showwarning("Operation in progress", "Stop or wait for the current operation before starting another.")
            return
        self.container_name = container_name
        self.operation_active = True
        self.operation_name = operation_name
        self.operation_stage = initial_operation_stage(operation_name)
        self.lines.put("\nCOMMAND: " + subprocess.list2cmdline(command) + "\n\n")
        self.lines.put("[START] " + operation_start_message(operation_name) + "\n")
        self._set_running(True)

        def worker() -> None:
            try:
                self.process = subprocess.Popen(
                    command,
                    cwd=project,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                assert self.process.stdout is not None
                for line in self.process.stdout:
                    self.operation_stage = stage_from_progress_line(self.operation_stage, line)
                    self.lines.put(line)
                code = self.process.wait()
                self.lines.put(f"\nProcess finished with exit code {code}.\n")
            except FileNotFoundError:
                self.lines.put("\nLauncher error: Docker was not found. Install/start Docker Desktop or Docker Engine.\n")
            except Exception as exc:  # GUI boundary: report unexpected host errors to the operator.
                self.lines.put(f"\nLauncher error: {exc}\n")
            finally:
                self.process = None
                self.container_name = None
                self.operation_active = False
                self.operation_name = ""
                self.operation_stage = "processing"
                self.after(0, self._refresh_scope_selectors)
                self.after(0, self._refresh_hunt_report_selectors)
                self.after(0, lambda: self._set_running(False))

        threading.Thread(target=worker, daemon=True).start()

    def _heartbeat(self) -> None:
        if self.operation_active:
            self.lines.put("[HEARTBEAT] " + operation_heartbeat_message(self.operation_stage) + "\n")
        self.after(HEARTBEAT_INTERVAL_MS, self._heartbeat)

    def _set_running(self, running: bool) -> None:
        state = "disabled" if running else "normal"
        for button in self.action_buttons:
            button.configure(state=state)
        self.stop_button.configure(state="normal" if running else "disabled")
        self.status.set("Operation running…" if running else "Ready")

    def stop(self) -> None:
        if self.process is None:
            return
        name = self.container_name
        self.lines.put("\nStopping the current Docker container…\n")

        def stopper() -> None:
            if name:
                try:
                    subprocess.run(
                        ["docker", "stop", "-t", "10", name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                except Exception as exc:
                    self.lines.put(f"Stop warning: {exc}\n")
            process = self.process
            if process is not None and process.poll() is None:
                process.terminate()

        threading.Thread(target=stopper, daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                line = self.lines.get_nowait()
                self.output.insert("end", line)
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _close(self) -> None:
        if self.process is not None:
            if not messagebox.askyesno("Operation running", "Stop the current operation and close the launcher?"):
                return
            self.stop()
        self.destroy()


if __name__ == "__main__":
    ThreadsawLauncher().mainloop()
