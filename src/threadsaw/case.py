from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from . import MOTTO, PROJECT_NAME, __version__
from .db import connect_db, initialize_schema
from .security import security_posture
from .util import atomic_write_json, utc_now

CASE_FILE = "case.json"
DB_FILE = "threadsaw.sqlite3"

DEFAULT_CONFIG: dict[str, Any] = {
    "organization_domains": [],
    "default_date_policy": "best",
}


def initialize_case(case_dir: Path) -> dict[str, Any]:
    case_dir = case_dir.resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    for name in ("logs", "extracted", "sources/eml", "sources/msg", "artifacts/attachments", "reports", "exports", "selections", "configs/phish_hunt"):
        (case_dir / name).mkdir(parents=True, exist_ok=True)
    case_path = case_dir / CASE_FILE
    if case_path.exists():
        data = load_case(case_dir)
    else:
        data = {
            "project": PROJECT_NAME,
            "motto": MOTTO,
            "application_version": __version__,
            "schema_version": 8,
            "case_id": str(uuid.uuid4()),
            "created_utc": utc_now(),
            "security_guardrails": security_posture(),
            "config": DEFAULT_CONFIG.copy(),
        }
        atomic_write_json(case_path, data)
    conn = connect_db(case_dir)
    try:
        initialize_schema(conn)
    finally:
        conn.close()
    changed = False
    if data.get("schema_version", 0) < 8:
        data["schema_version"] = 8
        changed = True
    if not data.get("case_id"):
        data["case_id"] = str(uuid.uuid4())
        changed = True
    if data.get("application_version") != __version__:
        data["application_version"] = __version__
        changed = True
    posture = security_posture()
    if data.get("security_guardrails") != posture:
        data["security_guardrails"] = posture
        changed = True
    if changed:
        atomic_write_json(case_path, data)
    return data


def load_case(case_dir: Path) -> dict[str, Any]:
    path = case_dir.resolve() / CASE_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"Not a Threadsaw case: {case_dir}. Run `threadsaw ingest --input ... --case ...` "
            "or `threadsaw run --input ... --case ...` first."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("project") != PROJECT_NAME:
        raise ValueError(f"Case metadata does not identify a {PROJECT_NAME} case")
    changed = False
    if not data.get("case_id"):
        data["case_id"] = str(uuid.uuid4())
        changed = True
    if data.get("schema_version", 0) < 8:
        data["schema_version"] = 8
        changed = True
    if changed:
        atomic_write_json(path, data)
    return data


def update_case(case_dir: Path, data: dict[str, Any]) -> None:
    atomic_write_json(case_dir.resolve() / CASE_FILE, data)
