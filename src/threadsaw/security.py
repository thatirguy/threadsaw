"""Non-negotiable runtime security guardrails for Threadsaw.

Threadsaw is an offline static-analysis tool. It does not resolve or connect to
IP addresses, follow or retrieve URLs, launch browser handlers, or launch or
execute attachments. The only permitted child process is the fixed `readpst`
executable used for PST extraction.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import urllib.request
import webbrowser
from pathlib import Path
from typing import Iterable


class SecurityGuardrailError(RuntimeError):
    """Raised when a prohibited network, launch, or execution action is attempted."""


_ORIGINAL_POPEN = subprocess.Popen
_GUARDRAILS_INSTALLED = False


def _deny_network(*_args, **_kwargs):
    raise SecurityGuardrailError(
        "Threadsaw forbids all network access, including DNS resolution and URL/IP connections."
    )


def _deny_launch(*_args, **_kwargs):
    raise SecurityGuardrailError(
        "Threadsaw forbids launching external programs, URLs, IP addresses, or attachments."
    )


def install_runtime_guardrails() -> None:
    """Deny network access and general-purpose process/application launching.

    This is defense in depth. The source code also contains no network client and
    Docker examples use `--network none`. The readpst adapter bypasses the general
    process denial only through :func:`run_readpst`, which resolves and executes
    that one allowlisted binary with a list-form argument vector and no shell.
    """
    global _GUARDRAILS_INSTALLED
    if _GUARDRAILS_INSTALLED:
        return

    # Network and URL handling. urllib/http clients ultimately use sockets, but
    # explicit patches make the policy immediate and auditable.
    socket.socket = _deny_network  # type: ignore[assignment]
    socket.create_connection = _deny_network  # type: ignore[assignment]
    socket.getaddrinfo = _deny_network  # type: ignore[assignment]
    if hasattr(socket, "create_server"):
        socket.create_server = _deny_network  # type: ignore[assignment]
    urllib.request.urlopen = _deny_network  # type: ignore[assignment]
    urllib.request.build_opener = _deny_network  # type: ignore[assignment]
    webbrowser.open = _deny_launch  # type: ignore[assignment]
    webbrowser.open_new = _deny_launch  # type: ignore[assignment]
    webbrowser.open_new_tab = _deny_launch  # type: ignore[assignment]

    # Deny general-purpose child processes and OS application launchers. The
    # original Popen object is retained privately for the readpst-only wrapper.
    subprocess.Popen = _deny_launch  # type: ignore[assignment]
    subprocess.run = _deny_launch  # type: ignore[assignment]
    subprocess.call = _deny_launch  # type: ignore[assignment]
    subprocess.check_call = _deny_launch  # type: ignore[assignment]
    subprocess.check_output = _deny_launch  # type: ignore[assignment]
    os.system = _deny_launch  # type: ignore[assignment]
    os.popen = _deny_launch  # type: ignore[assignment]
    if hasattr(os, "startfile"):
        os.startfile = _deny_launch  # type: ignore[attr-defined,assignment]

    _GUARDRAILS_INSTALLED = True


def _offline_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in list(env):
        if name.lower() in {
            "http_proxy", "https_proxy", "ftp_proxy", "all_proxy",
            "http_proxy_request_fulluri", "https_proxy_request_fulluri",
        }:
            env.pop(name, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def run_readpst(
    arguments: Iterable[str], *, timeout: float | None, executable_path: Path | str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run only the explicitly configured or locally installed readpst binary.

    ``THREADSAW_READPST`` or ``executable_path`` can pin a trusted absolute
    executable instead of relying on PATH resolution for native host use.
    """
    configured = executable_path or os.environ.get("THREADSAW_READPST")
    executable = str(configured) if configured else shutil.which("readpst")
    if not executable:
        raise FileNotFoundError("readpst was not found; install it or set THREADSAW_READPST to an absolute readpst path")
    raw_path = Path(executable).expanduser()
    if configured and not raw_path.is_absolute():
        raise SecurityGuardrailError("Configured readpst path must be absolute")
    executable_path = raw_path.resolve()
    if executable_path.name.lower() not in {"readpst", "readpst.exe"}:
        raise SecurityGuardrailError(f"Resolved PST extractor is not readpst: {executable_path}")
    if not executable_path.is_file():
        raise FileNotFoundError(f"Configured readpst executable does not exist: {executable_path}")

    argv = [str(executable_path), *(str(value) for value in arguments)]
    process = _ORIGINAL_POPEN(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        env=_offline_environment(),
        close_fds=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout=stdout, stderr=stderr)


def security_posture() -> dict[str, object]:
    return {
        "network_access": "denied",
        "dns_resolution": "denied",
        "url_following_or_retrieval": False,
        "ip_connection_or_enrichment": False,
        "browser_or_os_url_launch": False,
        "attachment_launch_or_execution": False,
        "attachment_handling": "static byte parsing, hashing, copying, and reporting only",
        "external_process_allowlist": ["readpst"],
    }
