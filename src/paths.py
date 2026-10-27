"""Filesystem layout for a Vagruw project."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectPaths:
    """Resolve every project and runtime path from one root directory."""

    root: Path

    def __init__(self, root: str | Path) -> None:
        object.__setattr__(self, "root", Path(root).expanduser().resolve())

    @property
    def vagrantfile(self) -> Path:
        """Return the generated Vagrantfile path."""
        return self.root / "Vagrantfile"

    @property
    def config(self) -> Path:
        """Return the user-editable configuration path."""
        return self.root / "vagruw.json"

    @property
    def gitignore(self) -> Path:
        """Return the project gitignore path."""
        return self.root / ".gitignore"

    @property
    def runtime(self) -> Path:
        """Return the private runtime directory."""
        return self.root / ".vagruw"

    @property
    def artifacts(self) -> Path:
        """Return the directory that caches downloaded installers."""
        return self.runtime / "artifacts"

    @property
    def remote_config(self) -> Path:
        """Return the generated config.yml used by the Wazuh installer."""
        return self.runtime / "config.yml"

    @property
    def archive(self) -> Path:
        """Return the downloaded Wazuh installation archive."""
        return self.runtime / "wazuh-install-files.tar"

    @property
    def credentials(self) -> Path:
        """Return the extracted credential listing."""
        return self.runtime / "credentials.txt"

    def installer(self, version: str) -> Path:
        """Return the cached installer path for a pinned version."""
        return self.artifacts / f"wazuh-install-{version}.sh"

    def ensure_runtime(self) -> None:
        """Create the private runtime directories with restrictive permissions."""
        self.runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
