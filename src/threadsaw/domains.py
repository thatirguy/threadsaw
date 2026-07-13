"""Offline registrable-domain helpers backed by a vendored Public Suffix List.

The list is packaged with Threadsaw and never refreshed at runtime.  This keeps
all domain comparisons deterministic and network-free.
"""
from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import ipaddress

PSL_SNAPSHOT = "2026-07-09"


@lru_cache(maxsize=1)
def _rules() -> tuple[set[str], set[str], set[str]]:
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    resource = files("threadsaw").joinpath("data/public_suffix_list.dat")
    with resource.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            try:
                line = line.encode("idna").decode("ascii").lower()
            except UnicodeError:
                line = line.lower()
            if line.startswith("!"):
                exception.add(line[1:])
            elif line.startswith("*."):
                wildcard.add(line[2:])
            else:
                normal.add(line)
    return normal, wildcard, exception


def normalize_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    host = str(hostname).strip().strip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host.strip("[]")
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host


def public_suffix(hostname: str | None) -> str | None:
    host = normalize_hostname(hostname)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    normal, wildcard, exception = _rules()

    matched = labels[-1]
    matched_len = 1
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            # Exception rules remove their left-most label from the public suffix.
            return ".".join(labels[i + 1 :])
        if candidate in normal:
            length = len(labels) - i
            if length > matched_len:
                matched, matched_len = candidate, length
        if i + 1 < len(labels):
            wildcard_base = ".".join(labels[i + 1 :])
            if wildcard_base in wildcard:
                length = len(labels) - i
                if length > matched_len:
                    matched, matched_len = candidate, length
    return matched


def registrable_domain(hostname: str | None) -> str | None:
    host = normalize_hostname(hostname)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    suffix = public_suffix(host)
    if not suffix:
        return host
    labels = host.split(".")
    suffix_labels = suffix.split(".")
    if len(labels) <= len(suffix_labels):
        return host
    return ".".join(labels[-(len(suffix_labels) + 1) :])
