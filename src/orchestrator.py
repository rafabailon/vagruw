"""Deployment lifecycle and Wazuh installation orchestration."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shlex
import shutil
import tarfile
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from config import load_deployment, save_deployment
from constants import __version__
from generator import render_vagrantfile
from model import ROLE_DASHBOARD, ROLE_INDEXER, ROLE_SERVER, Deployment
from paths import ProjectPaths
from runner import Runner
from wazuh import (
    REMOTE_ARCHIVE,
    REMOTE_CONFIG,
    REMOTE_DIR,
    REMOTE_INSTALLER,
    InstallerVersionMismatch,
    WazuhProfile,
    all_in_one_command,
    cleanup_command,
    cluster_health_command,
    component_command,
    extract_admin_password,
    generate_config_command,
    profile_for,
    render_config_yaml,
    service_check_command,
    start_cluster_command,
    verify_installer_file,
)

InstallFetcher = Callable[[WazuhProfile, Path], None]


class OrchestrationError(RuntimeError):
    """Raised when a deployment action cannot be completed safely."""


@dataclass(frozen=True)
class UploadAction:
    """Copy a local file to a machine through vagrant upload."""

    local: Path
    remote: str
    machine: str
    description: str


@dataclass(frozen=True)
class SshAction:
    """Run one shell command on a machine."""

    machine: str
    command: str
    description: str
    capture: bool = False


@dataclass(frozen=True)
class FetchAction:
    """Read a remote file over SSH and store it locally."""

    machine: str
    remote: str
    local: Path
    description: str


Action = UploadAction | SshAction | FetchAction


def _download_installer(profile: WazuhProfile, destination: Path) -> None:
    """Download the pinned installer from the official Wazuh package host."""
    request = urllib.request.Request(
        profile.installer_url,
        headers={"User-Agent": f"vagruw/{__version__}"},
    )
    partial = destination.with_suffix(destination.suffix + ".part")
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            partial.open("wb") as handle,
        ):
            shutil.copyfileobj(response, handle)
        os.replace(partial, destination)
    finally:
        if partial.exists():
            partial.unlink()


def decode_base64_output(output: str) -> bytes:
    """Decode base64 emitted by a remote shell while ignoring vagrant prefixes."""
    lines = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("==>"):
            continue
        lines.append(stripped)
    encoded = "".join(lines)
    if not encoded or not re.fullmatch(r"[A-Za-z0-9+/=]+", encoded):
        raise OrchestrationError(
            "The remote file transfer did not return valid base64 data."
        )
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise OrchestrationError("The remote archive could not be decoded.") from error


def extract_credentials(archive: Path, destination: Path) -> str:
    """Extract wazuh-passwords.txt from the installer archive."""
    try:
        with tarfile.open(archive, "r:*") as handle:
            member = next(
                (
                    item
                    for item in handle.getmembers()
                    if item.name.endswith("wazuh-passwords.txt")
                ),
                None,
            )
            if member is None:
                raise OrchestrationError(
                    f"The archive {archive} does not contain wazuh-passwords.txt."
                )
            extracted = handle.extractfile(member)
            if extracted is None:
                raise OrchestrationError(
                    f"The archive {archive} contains an unreadable password entry."
                )
            content = extracted.read()
    except (tarfile.TarError, OSError) as error:
        raise OrchestrationError(
            f"Could not read the Wazuh archive {archive}."
        ) from error
    header = (
        "# Credentials extracted by Vagruw from the Wazuh installation archive.\n"
        "# Keep this file private and never commit it to version control.\n"
    )
    text = header + content.decode("utf-8", errors="replace")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    destination.chmod(0o600)
    return text


def build_install_plan(
    deployment: Deployment,
    profile: WazuhProfile,
    installer: Path,
    config_file: Path,
    archive: Path,
    overwrite: bool = False,
) -> list[Action]:
    """Build the ordered actions required to install Wazuh on the lab."""
    ignore_check = deployment.ignore_hardware_check
    actions: list[Action] = []
    for node in deployment.nodes:
        actions.append(
            UploadAction(
                local=installer,
                remote=REMOTE_INSTALLER,
                machine=node.name,
                description=f"Upload the Wazuh {profile.version} installer to {node.name}",
            )
        )
    if deployment.is_aio:
        node = deployment.control_node
        actions.append(
            SshAction(
                machine=node.name,
                command=all_in_one_command(profile, ignore_check, overwrite),
                description=f"Install Wazuh {profile.version} all-in-one on {node.name}",
            )
        )
        actions.append(
            FetchAction(
                machine=node.name,
                remote=REMOTE_ARCHIVE,
                local=archive,
                description="Download the generated credentials archive",
            )
        )
        actions.append(
            SshAction(
                machine=node.name,
                command=cleanup_command(),
                description=f"Remove installer files and credentials from {node.name}",
            )
        )
        return actions
    control = deployment.control_node
    actions.append(
        UploadAction(
            local=config_file,
            remote=REMOTE_CONFIG,
            machine=control.name,
            description=f"Upload the Wazuh node configuration to {control.name}",
        )
    )
    actions.append(
        SshAction(
            machine=control.name,
            command=generate_config_command(profile),
            description="Generate certificates, cluster key, and passwords",
        )
    )
    actions.append(
        FetchAction(
            machine=control.name,
            remote=REMOTE_ARCHIVE,
            local=archive,
            description="Download the generated credentials archive",
        )
    )
    for node in deployment.nodes:
        actions.append(
            SshAction(
                machine=node.name,
                command=f"sudo -n rm -f {shlex.quote(REMOTE_ARCHIVE)}",
                description=f"Clear the previous archive on {node.name}",
            )
        )
        actions.append(
            UploadAction(
                local=archive,
                remote=REMOTE_ARCHIVE,
                machine=node.name,
                description=f"Upload the installation archive to {node.name}",
            )
        )
    for node in deployment.indexer_nodes:
        actions.append(
            SshAction(
                machine=node.name,
                command=component_command(
                    profile,
                    node.name,
                    ROLE_INDEXER,
                    ignore_check,
                    overwrite,
                ),
                description=f"Install and start the Wazuh indexer on {node.name}",
            )
        )
    actions.append(
        SshAction(
            machine=control.name,
            command=start_cluster_command(profile),
            description="Initialize the Wazuh indexer cluster security settings",
        )
    )
    for node in deployment.server_nodes:
        actions.append(
            SshAction(
                machine=node.name,
                command=component_command(
                    profile,
                    node.name,
                    ROLE_SERVER,
                    ignore_check,
                    overwrite,
                ),
                description=f"Install and start the Wazuh server on {node.name}",
            )
        )
    for node in deployment.dashboard_nodes:
        actions.append(
            SshAction(
                machine=node.name,
                command=component_command(
                    profile,
                    node.name,
                    ROLE_DASHBOARD,
                    ignore_check,
                    overwrite,
                ),
                description=f"Install and start the Wazuh dashboard on {node.name}",
            )
        )
    for node in deployment.nodes:
        actions.append(
            SshAction(
                machine=node.name,
                command=cleanup_command(),
                description=f"Remove installer files and credentials from {node.name}",
            )
        )
    return actions


def format_action(action: Action, index: int, total: int) -> str:
    """Return a readable representation of one plan action."""
    prefix = f"[{index}/{total}]"
    if isinstance(action, UploadAction):
        return f"{prefix} {action.description}: {action.local} -> {action.machine}:{action.remote}"
    if isinstance(action, FetchAction):
        return f"{prefix} {action.description}: {action.machine}:{action.remote} -> {action.local}"
    return f"{prefix} {action.description}: {action.machine}$ {action.command}"


class DeploymentManager:
    """Coordinate Vagrant and the Wazuh installation assistant."""

    def __init__(
        self,
        root: str | Path,
        *,
        runner: Runner | None = None,
        installer_fetcher: InstallFetcher | None = None,
        installer_source: str | Path | None = None,
    ) -> None:
        self.paths = ProjectPaths(root)
        self.runner = runner or Runner()
        self.installer_fetcher = installer_fetcher or _download_installer
        self.installer_source = Path(installer_source) if installer_source else None

    @property
    def deployment(self) -> Deployment:
        """Load the current deployment from disk."""
        return load_deployment(self.paths.config)

    def generate(self, force: bool = False) -> Path:
        """Render the Vagrantfile from the configuration file."""
        deployment = self.deployment
        if self.paths.vagrantfile.exists() and not force:
            raise FileExistsError(
                f"{self.paths.vagrantfile} already exists. Use 'vagruw generate --force' to replace it."
            )
        self.paths.vagrantfile.write_text(
            render_vagrantfile(deployment), encoding="utf-8"
        )
        return self.paths.vagrantfile

    def ensure_vagrantfile(self) -> Path:
        """Create the Vagrantfile when it is missing and leave it untouched otherwise."""
        if not self.paths.vagrantfile.exists():
            self.paths.vagrantfile.write_text(
                render_vagrantfile(self.deployment),
                encoding="utf-8",
            )
        return self.paths.vagrantfile

    def write_config_yaml(self, deployment: Deployment, profile: WazuhProfile) -> Path:
        """Write the config.yml consumed by the Wazuh assisted installer."""
        self.paths.ensure_runtime()
        self.paths.remote_config.write_text(
            render_config_yaml(deployment, profile),
            encoding="utf-8",
        )
        return self.paths.remote_config

    def ensure_installer(self, profile: WazuhProfile) -> Path:
        """Return a verified local installer, downloading or copying it if needed."""
        self.paths.ensure_runtime()
        destination = self.paths.installer(profile.version)
        if destination.exists():
            try:
                verify_installer_file(str(destination), profile)
                return destination
            except InstallerVersionMismatch:
                destination.unlink()
        source = self.installer_source
        if source is None and os.environ.get("VAGRUW_INSTALLER_SOURCE"):
            source = Path(os.environ["VAGRUW_INSTALLER_SOURCE"])
        if source is not None:
            if not source.is_file():
                raise OrchestrationError(
                    f"The installer source {source} does not exist."
                )
            shutil.copyfile(source, destination)
        else:
            try:
                self.installer_fetcher(profile, destination)
            except Exception as error:
                if destination.exists():
                    destination.unlink()
                raise OrchestrationError(
                    f"Could not download the Wazuh installer from {profile.installer_url}: {error}"
                ) from error
        verify_installer_file(str(destination), profile)
        destination.chmod(0o700)
        return destination

    def install(self, *, overwrite: bool = False, dry_run: bool = False) -> None:
        """Install and configure Wazuh on the existing machines."""
        deployment = self.deployment
        profile = profile_for(deployment.wazuh_version)
        installer = self.paths.installer(profile.version)
        config_file = self.paths.remote_config
        actions = build_install_plan(
            deployment,
            profile,
            installer,
            config_file,
            self.paths.archive,
            overwrite=overwrite,
        )
        if dry_run:
            print(
                f"Installation plan for Wazuh {profile.version} ({deployment.topology}):"
            )
            for index, action in enumerate(actions, start=1):
                print(format_action(action, index, len(actions)))
            return
        self.ensure_vagrantfile()
        self.paths.ensure_runtime()
        installer = self.ensure_installer(profile)
        self.write_config_yaml(deployment, profile)
        actions = build_install_plan(
            deployment,
            profile,
            installer,
            config_file,
            self.paths.archive,
            overwrite=overwrite,
        )
        self._execute(actions)
        text = extract_credentials(self.paths.archive, self.paths.credentials)
        password = extract_admin_password(text)
        print()
        print(f"Wazuh {profile.version} installation finished.")
        print(f"Dashboard: {deployment.dashboard_url}")
        print(f"Credentials: {self.paths.credentials} (mode 600)")
        if password:
            print("Wazuh dashboard user: admin")
            print("The admin password is stored in the credentials file.")

    def _execute(self, actions: Iterable[Action]) -> None:
        actions = list(actions)
        prepared_machines: set[str] = set()
        for index, action in enumerate(actions, start=1):
            print(format_action(action, index, len(actions)), flush=True)
            if isinstance(action, UploadAction):
                if action.machine not in prepared_machines:
                    self._ssh(
                        action.machine,
                        "mkdir -p "
                        f"{shlex.quote(REMOTE_DIR)} && chmod 700 {shlex.quote(REMOTE_DIR)}",
                    )
                    prepared_machines.add(action.machine)
                self.runner.run(
                    [
                        "vagrant",
                        "upload",
                        str(action.local),
                        action.remote,
                        action.machine,
                    ],
                    cwd=self.paths.root,
                )
            elif isinstance(action, FetchAction):
                result = self._ssh(
                    action.machine,
                    f"sudo -n base64 -w0 {shlex.quote(action.remote)}",
                    capture=True,
                )
                data = decode_base64_output(result.stdout)
                action.local.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(
                    action.local,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                action.local.chmod(0o600)
            else:
                self._ssh(action.machine, action.command, capture=action.capture)

    def _ssh(self, machine: str, command: str, *, capture: bool = False):
        return self.runner.run(
            ["vagrant", "ssh", machine, "-c", command],
            cwd=self.paths.root,
            capture=capture,
        )

    def up(self, *, no_install: bool = False, reprovision: bool = False) -> None:
        """Start every machine and install Wazuh unless installation is skipped."""
        deployment = self.deployment
        self.ensure_vagrantfile()
        arguments = ["vagrant", "up", "--provider", deployment.provider]
        if reprovision:
            arguments.append("--provision")
        self.runner.run(arguments, cwd=self.paths.root)
        if not no_install:
            self.install()

    def halt(self, machine_name: str | None = None) -> None:
        """Stop one machine, or every machine, without deleting its disk."""
        self.ensure_vagrantfile()
        arguments = ["vagrant", "halt"]
        if machine_name:
            arguments.append(self.deployment.node(machine_name).name)
        self.runner.run(arguments, cwd=self.paths.root)

    def destroy(self, *, purge: bool = False) -> None:
        """Delete every machine and optionally remove private runtime data."""
        self.ensure_vagrantfile()
        self.runner.run(["vagrant", "destroy", "-f"], cwd=self.paths.root)
        if purge and self.paths.runtime.exists():
            shutil.rmtree(self.paths.runtime)

    def status(self) -> None:
        """Show Vagrant status for the lab."""
        self.ensure_vagrantfile()
        self.runner.run(["vagrant", "status"], cwd=self.paths.root)

    def ssh(self, machine_name: str, command: str | None = None) -> None:
        """Open an interactive SSH session or run one command on a machine."""
        deployment = self.deployment
        node = deployment.node(machine_name)
        arguments = ["vagrant", "ssh", node.name]
        if command:
            arguments.extend(["-c", command])
        self.runner.run(arguments, cwd=self.paths.root)

    def credentials(self) -> str:
        """Return the extracted credential listing, failing when it is absent."""
        if not self.paths.credentials.exists():
            raise OrchestrationError(
                "No credentials were found. Run 'vagruw install' first."
            )
        return self.paths.credentials.read_text(encoding="utf-8")

    def verify(self) -> bool:
        """Check services and, when credentials exist, indexer cluster health."""
        deployment = self.deployment
        healthy = True
        for node in deployment.nodes:
            result = self._ssh(
                node.name, service_check_command(node.services), capture=True
            )
            states = {}
            for line in result.stdout.splitlines():
                if "=" in line:
                    service, state = line.split("=", 1)
                    states[service] = state.strip()
            for service in node.services:
                state = states.get(service, "unknown")
                print(f"{node.name}: {service} is {state}")
                if state != "active":
                    healthy = False
        if not self.paths.credentials.exists():
            print("Cluster health was not checked because no credentials file exists.")
            return healthy
        password = extract_admin_password(self.credentials())
        if not password:
            print(
                "Cluster health was not checked because the admin password was not found."
            )
            return healthy
        control = deployment.control_node
        result = self._ssh(control.name, cluster_health_command(password), capture=True)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(
                f"Indexer cluster health check returned unreadable output: {result.stdout.strip()}"
            )
            return False
        status = str(payload.get("status", "unknown"))
        print(f"Wazuh indexer cluster status: {status}")
        if status not in {"green", "yellow"}:
            healthy = False
        print(f"Dashboard: {deployment.dashboard_url}")
        return healthy


def initialise_project(
    root: str | Path,
    deployment: Deployment,
    *,
    force: bool = False,
) -> tuple[Path, Path]:
    """Write the configuration, Vagrantfile, and protective gitignore."""
    paths = ProjectPaths(root)
    for target in (paths.config, paths.vagrantfile):
        if target.exists() and not force:
            raise FileExistsError(
                f"{target} already exists. Use --force to replace the generated files."
            )
    paths.root.mkdir(parents=True, exist_ok=True)
    save_deployment(paths.config, deployment)
    paths.vagrantfile.write_text(render_vagrantfile(deployment), encoding="utf-8")
    _ensure_gitignore(paths)
    return paths.config, paths.vagrantfile


def _ensure_gitignore(paths: ProjectPaths) -> None:
    """Append the private runtime paths to an existing gitignore when needed."""
    entries = [
        ".vagrant/",
        ".vagruw/",
        "*.log",
        "wazuh-install-files.tar",
        "credentials.txt",
    ]
    existing = (
        paths.gitignore.read_text(encoding="utf-8") if paths.gitignore.exists() else ""
    )
    missing = [entry for entry in entries if entry not in existing.splitlines()]
    if not missing:
        return
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    block = "# Vagruw runtime and credential files.\n" if not existing else ""
    paths.gitignore.write_text(
        existing + prefix + block + "\n".join(missing) + "\n",
        encoding="utf-8",
    )
