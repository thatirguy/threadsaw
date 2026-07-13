from __future__ import annotations

import ast
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from threadsaw.db import SCHEMA, connect_db, initialize_schema
from threadsaw.security import SecurityGuardrailError, install_runtime_guardrails, run_readpst, security_posture


class SecurityGuardrailTest(unittest.TestCase):
    def test_source_has_no_network_clients_or_general_subprocess_imports(self):
        banned_roots = {
            "requests", "httpx", "aiohttp", "ftplib", "smtplib", "telnetlib",
            "websocket", "imaplib", "poplib", "nntplib", "paramiko",
        }
        guarded_modules = {"socket", "webbrowser", "urllib.request", "http.client", "xmlrpc.client"}
        allowed_network_module = ROOT / "src" / "threadsaw" / "security.py"
        banned_os_calls = {"system", "popen", "startfile", "spawnl", "spawnlp", "spawnv", "spawnvp"}
        banned_subprocess_calls = {"Popen", "run", "call", "check_call", "check_output"}
        for path in (ROOT / "src" / "threadsaw").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        full = alias.name
                        root = full.split(".", 1)[0]
                        self.assertNotIn(root, banned_roots, f"network client imported by {path}")
                        if full in guarded_modules or root in {"socket", "webbrowser"}:
                            self.assertEqual(path, allowed_network_module)
                        if root == "subprocess":
                            self.assertEqual(path, allowed_network_module)
                elif isinstance(node, ast.ImportFrom):
                    full = node.module or ""
                    root = full.split(".", 1)[0]
                    self.assertNotIn(root, banned_roots, f"network client imported by {path}")
                    if full in guarded_modules or root in {"socket", "webbrowser"}:
                        self.assertEqual(path, allowed_network_module)
                    if root == "subprocess":
                        imported = {alias.name for alias in node.names}
                        self.assertEqual(imported, {"CompletedProcess"})
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    owner = node.func.value
                    if isinstance(owner, ast.Name) and owner.id == "os" and node.func.attr in banned_os_calls:
                        self.assertEqual(path, allowed_network_module)
                    if isinstance(owner, ast.Name) and owner.id == "subprocess" and node.func.attr in banned_subprocess_calls:
                        self.assertEqual(path, allowed_network_module)

    def test_runtime_denies_network_browser_and_general_process_launch(self):
        install_runtime_guardrails()
        denied_calls = [
            lambda: socket.socket(),
            lambda: socket.getaddrinfo("example.com", 443),
            lambda: urllib.request.urlopen("https://example.com"),
            lambda: webbrowser.open("https://example.com"),
            lambda: subprocess.Popen(["echo", "not-allowed"]),
            lambda: subprocess.run(["echo", "not-allowed"]),
            lambda: os.system("echo not-allowed"),
        ]
        for call in denied_calls:
            with self.assertRaises(SecurityGuardrailError):
                call()
        self.assertIsInstance(subprocess.Popen, type)
        posture = security_posture()
        self.assertEqual(posture["network_access"], "denied")
        self.assertFalse(posture["attachment_launch_or_execution"])

    def test_readpst_wrapper_rejects_a_non_readpst_executable(self):
        from unittest.mock import patch

        with patch("threadsaw.security.shutil.which", return_value="/tmp/not-readpst-tool"):
            with self.assertRaises(SecurityGuardrailError):
                run_readpst(["-V"], timeout=1)

    def test_pre_0_1_1_identifier_columns_are_migrated_without_rehashing(self):
        with tempfile.TemporaryDirectory() as temp:
            case = Path(temp)
            conn = connect_db(case)
            try:
                conn.executescript(SCHEMA.replace("message_sha256", "threadsaw_id"))
                value = "a" * 64
                conn.execute(
                    """INSERT INTO messages(
                       threadsaw_id,format,derivation_status,eml_path,sender_ips_json,
                       defects_json,attachment_count,has_attachments,indexed_utc
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (value, "EML", "original-eml", "/tmp/test.eml", "[]", "[]", 0, 0, "2026-07-11T00:00:00Z"),
                )
                conn.commit()
                initialize_schema(conn)
                columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
                self.assertIn("message_sha256", columns)
                self.assertNotIn("threadsaw_id", columns)
                self.assertEqual(
                    conn.execute("SELECT message_sha256 FROM messages").fetchone()[0], value
                )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
