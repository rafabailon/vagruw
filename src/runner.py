"""Subprocess execution with a small, testable interface."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class CommandError(RuntimeError):
    """Raised when an external command exits with a non-zero status."""

    def __init__(
        self, arguments: Sequence[str], returncode: int, stderr: str = ""
    ) -> None:
        self.arguments = tuple(arguments)
        self.returncode = returncode
        self.stderr = stderr
        detail = (
            f"Command failed with exit code {returncode}: {' '.join(self.arguments)}"
        )
        if stderr.strip():
            detail = f"{detail}\n{stderr.strip()}"
        super().__init__(detail)


@dataclass(frozen=True)
class Result:
    """The captured result of a command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


class Runner:
    """Run local commands and optionally capture their output."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: str | Path | None = None,
        capture: bool = False,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> Result:
        """Execute a command and return its result."""
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        completed = subprocess.run(
            list(arguments),
            cwd=str(cwd) if cwd is not None else None,
            capture_output=capture,
            text=True,
            env=full_env,
            check=False,
        )
        result = Result(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and result.returncode != 0:
            raise CommandError(arguments, result.returncode, result.stderr)
        return result
