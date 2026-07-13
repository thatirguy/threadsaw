from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable

ProgressCallback = Callable[[str], None]


def console_progress(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


@dataclass
class ProgressCounter:
    label: str
    total: int
    callback: ProgressCallback = console_progress
    every: int = 100

    def update(self, current: int, *, detail: str | None = None, force: bool = False) -> None:
        if not force and current not in {1, self.total} and current % self.every != 0:
            return
        suffix = f" - {detail}" if detail else ""
        self.callback(f"[{self.label}] {current:,}/{self.total:,}{suffix}")
