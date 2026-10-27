"""Shared fixtures and fakes for the Vagruw test suite."""

from __future__ import annotations

import base64
import sys
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from config import create_deployment
from model import TOPOLOGY_AIO, TOPOLOGY_DISTRIBUTED
from runner import Result

FAKE_INSTALLER = """#!/usr/bin/env bash
set -euo pipefail
readonly wazuh_major="4.14"
readonly wazuh_version="4.14.9"
echo "fake Wazuh installer"
"""


class RecordingRunner:
    """A Runner-compatible object that records calls and returns canned output."""

    def __init__(self, stdout_for=None) -> None:
        self.calls: list[list[str]] = []
        self.stdout_for = stdout_for

    def run(
        self, arguments, *, cwd=None, capture=False, check=True, env=None
    ) -> Result:
        self.calls.append(list(arguments))
        stdout = ""
        if self.stdout_for is not None and capture:
            stdout = self.stdout_for(list(arguments)) or ""
        return Result(returncode=0, stdout=stdout, stderr="")

    def commands(self) -> list[str]:
        return [" ".join(call) for call in self.calls]


@pytest.fixture
def aio_deployment():
    return create_deployment(topology=TOPOLOGY_AIO, project="vagruw")


@pytest.fixture
def distributed_deployment():
    return create_deployment(
        project="vagruw",
        topology=TOPOLOGY_DISTRIBUTED,
        indexers=3,
        servers=2,
    )


@pytest.fixture
def fake_installer(tmp_path: Path) -> Path:
    path = tmp_path / "wazuh-install-4.14.9.sh"
    path.write_text(FAKE_INSTALLER, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def credentials_archive(tmp_path: Path) -> Path:
    path = tmp_path / "wazuh-install-files.tar"
    content = (
        b"# Admin user for the web user interface and Wazuh indexer.\n"
        b"  indexer_username: 'admin'\n"
        b"  indexer_password: 'LabSecret123!'\n"
        b"\n"
        b"# Wazuh dashboard user for establishing the connection with the indexer.\n"
        b"  indexer_username: 'kibanaserver'\n"
        b"  indexer_password: 'AnotherSecret'\n"
    )
    info = tarfile.TarInfo("wazuh-install-files/wazuh-passwords.txt")
    info.size = len(content)
    info.mode = 0o600
    with tarfile.open(path, "w") as archive:
        import io

        archive.addfile(info, io.BytesIO(content))
    return path


@pytest.fixture
def archive_base64(credentials_archive: Path) -> str:
    return base64.b64encode(credentials_archive.read_bytes()).decode()


@pytest.fixture
def fake_vagrant(tmp_path: Path, credentials_archive: Path):
    """Install a fake vagrant executable and return its bin directory and log path."""
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    log = tmp_path / "vagrant.log"
    script = bin_dir / "vagrant"
    script.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "${VAGRUW_FAKE_LOG:?}"
if [ "$1" = "ssh" ]; then
case "$*" in
*"base64 -w0"*) base64 -w0 "${VAGRUW_FAKE_ARCHIVE:?}" ;;
*"systemctl is-active"*) printf 'wazuh-indexer=active\\nwazuh-manager=active\\nwazuh-dashboard=active\\n' ;;
*"_cluster/health"*) printf '{"status":"green"}\\n' ;;
*) exit 0 ;;
esac
elif [ "$1" = "status" ]; then
printf 'Current machine states:\\n\\nvagruw-aio running (virtualbox)\\n'
fi
exit 0
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return bin_dir, log
