from __future__ import annotations

import importlib.util
import os
import platform
import shutil
from pathlib import Path
from typing import Any

from . import MOTTO, PROJECT_NAME, __version__
from .db import connect_db, database_health
from .security import run_readpst, security_posture


def run_doctor(case_dir: Path | None = None) -> dict[str, Any]:
    readpst = os.environ.get("THREADSAW_READPST") or shutil.which("readpst")
    readpst_version = None
    if readpst:
        try:
            proc = run_readpst(["-V"], timeout=10)
            readpst_version = (proc.stdout or proc.stderr).strip()
        except Exception as exc:
            readpst_version = f"error: {exc}"
    result: dict[str, Any] = {
        "project": PROJECT_NAME,
        "motto": MOTTO,
        "version": __version__,
        "python": platform.python_version(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_implementation": platform.python_implementation(),
        },
        "readpst_available": bool(readpst),
        "readpst_path": readpst,
        "readpst_version": readpst_version,
        "extract_msg_available": importlib.util.find_spec("extract_msg") is not None,
        "opencv_qr_available": importlib.util.find_spec("cv2") is not None,
        "pypdfium2_available": importlib.util.find_spec("pypdfium2") is not None,
        "security_guardrails": security_posture(),
    }
    if case_dir:
        case_dir = case_dir.resolve()
        database = case_dir / "threadsaw.sqlite3"
        result.update({
            "case_path": str(case_dir),
            "case_exists": (case_dir / "case.json").exists(),
            "case_writable": case_dir.exists() and os_access_writable(case_dir),
            "free_bytes": shutil.disk_usage(case_dir if case_dir.exists() else case_dir.parent).free,
            "database_exists": database.exists(),
        })
        if database.exists():
            try:
                conn = connect_db(case_dir)
                try:
                    result["database"] = database_health(conn)
                finally:
                    conn.close()
            except Exception as exc:
                result["database"] = {
                    "ready": False,
                    "error": str(exc),
                }
    return result


def os_access_writable(path: Path) -> bool:
    try:
        probe = path / ".threadsaw-write-test"
        probe.write_text("test", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False
