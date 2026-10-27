"""Command-line interface for Vagruw."""

from __future__ import annotations

import argparse
import os
import sys

from config import (
    DEFAULT_BOX,
    DEFAULT_IP_START,
    DEFAULT_NETWORK,
    DEFAULT_PROJECT,
    DEFAULT_PROVIDER,
    ConfigError,
    create_deployment,
    load_deployment,
)
from constants import DEFAULT_WAZUH_VERSION
from model import (
    PROVIDER_LIBVIRT,
    PROVIDER_VIRTUALBOX,
    TOPOLOGY_AIO,
    TOPOLOGY_DISTRIBUTED,
)
from orchestrator import (
    DeploymentManager,
    OrchestrationError,
    initialise_project,
)
from paths import ProjectPaths
from runner import CommandError
from wazuh import extract_admin_password


def _is_interactive(assume_yes: bool = False) -> bool:
    """Return True only when prompting is safe and explicitly allowed."""
    return sys.stdin.isatty() and not assume_yes


def build_parser() -> argparse.ArgumentParser:
    """Build the complete command-line parser."""
    parser = argparse.ArgumentParser(
        prog="vagruw",
        description="Generate Vagrant labs for Wazuh and manage their lifecycle.",
    )
    parser.add_argument(
        "-C",
        "--project-dir",
        default=os.environ.get("VAGRUW_PROJECT", "."),
        help="Project directory that contains vagruw.json and Vagrantfile.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser(
        "init",
        help="Create vagruw.json, a Vagrantfile, and a protective .gitignore.",
    )
    init.add_argument("--project", default=DEFAULT_PROJECT, help="Machine name prefix.")
    init.add_argument(
        "--topology",
        choices=[TOPOLOGY_AIO, TOPOLOGY_DISTRIBUTED],
        default=None,
        help="Install every component on one machine or use a distributed topology.",
    )
    init.add_argument(
        "--provider",
        choices=[PROVIDER_VIRTUALBOX, PROVIDER_LIBVIRT],
        default=None,
        help="Vagrant provider used by the generated lab.",
    )
    init.add_argument(
        "--box",
        default=None,
        help="HashiCorp generic image, for example generic/ubuntu2204.",
    )
    init.add_argument(
        "--wazuh-version",
        default=None,
        help=f"Pinned Wazuh release (default: {DEFAULT_WAZUH_VERSION}).",
    )
    init.add_argument("--network", default=DEFAULT_NETWORK, help="Host-only IPv4 CIDR.")
    init.add_argument(
        "--ip-start",
        type=int,
        default=DEFAULT_IP_START,
        help="First host address offset.",
    )
    init.add_argument(
        "--indexers", type=int, default=None, help="Number of indexer nodes."
    )
    init.add_argument(
        "--servers", type=int, default=None, help="Number of Wazuh server nodes."
    )
    init.add_argument(
        "--cpus", type=int, default=None, help="Override CPU count for every machine."
    )
    init.add_argument(
        "--memory",
        type=int,
        default=None,
        metavar="MB",
        help="Override memory in megabytes for every machine.",
    )
    init.add_argument(
        "--ignore-hardware-check",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Pass the installer's ignore-hardware-check flag (default: enabled for lab VMs).",
    )
    init.add_argument(
        "--force", action="store_true", help="Replace existing generated files."
    )
    init.add_argument(
        "--yes", "-y", action="store_true", help="Use defaults without prompting."
    )

    generate = subparsers.add_parser(
        "generate", help="Regenerate the Vagrantfile from vagruw.json."
    )
    generate.add_argument(
        "--force", action="store_true", help="Replace an existing Vagrantfile."
    )

    up = subparsers.add_parser("up", help="Create the machines and install Wazuh.")
    up.add_argument("--no-install", action="store_true", help="Only run vagrant up.")
    up.add_argument(
        "--reprovision",
        action="store_true",
        help="Run the Vagrant base bootstrap again on every machine.",
    )

    install = subparsers.add_parser(
        "install", help="Install and configure Wazuh on existing machines."
    )
    install.add_argument(
        "--overwrite",
        action="store_true",
        help="Reinstall components and erase their existing data.",
    )
    install.add_argument(
        "--dry-run", action="store_true", help="Print the ordered actions only."
    )

    halt = subparsers.add_parser(
        "halt", help="Stop the machines without deleting them."
    )
    halt.add_argument("--machine", help="Stop only one machine.")

    destroy = subparsers.add_parser("destroy", help="Delete every machine in the lab.")
    destroy.add_argument(
        "--force", action="store_true", help="Do not ask for confirmation."
    )
    destroy.add_argument(
        "--purge",
        action="store_true",
        help="Also delete .vagruw, including cached installers and credentials.",
    )

    subparsers.add_parser("status", help="Show Vagrant status for every machine.")

    ssh = subparsers.add_parser("ssh", help="Open an SSH session or run a command.")
    ssh.add_argument(
        "machine", nargs="?", help="Machine name or short name such as indexer-1."
    )
    ssh.add_argument(
        "remote_command", nargs=argparse.REMAINDER, help="Command to run remotely."
    )

    subparsers.add_parser("verify", help="Check Wazuh services and cluster health.")

    credentials = subparsers.add_parser(
        "credentials", help="Show the dashboard access details."
    )
    credentials.add_argument(
        "--show", action="store_true", help="Print the full credentials file."
    )

    return parser


def _prompt_choice(
    label: str, choices: list[str], default: str, interactive: bool
) -> str:
    if not interactive:
        return default
    options = "/".join(choices)
    while True:
        answer = input(f"{label} [{options}] ({default}): ").strip()
        if not answer:
            return default
        if answer in choices:
            return answer
        print(f"Please choose one of: {options}.")


def _prompt_text(label: str, default: str, interactive: bool) -> str:
    if not interactive:
        return default
    answer = input(f"{label} ({default}): ").strip()
    return answer or default


def _prompt_int(label: str, default: int, interactive: bool) -> int:
    if not interactive:
        return default
    while True:
        answer = input(f"{label} ({default}): ").strip()
        if not answer:
            return default
        try:
            value = int(answer)
        except ValueError:
            print("Please enter an integer.")
            continue
        if value > 0:
            return value
        print("Please enter a positive integer.")


def _handle_init(args: argparse.Namespace) -> int:
    interactive = _is_interactive(args.yes)
    topology = args.topology
    if topology is None:
        topology = _prompt_choice(
            "Deployment topology",
            [TOPOLOGY_AIO, TOPOLOGY_DISTRIBUTED],
            TOPOLOGY_AIO,
            interactive,
        )
    provider = args.provider or _prompt_choice(
        "Vagrant provider",
        [PROVIDER_VIRTUALBOX, PROVIDER_LIBVIRT],
        DEFAULT_PROVIDER,
        interactive,
    )
    box = args.box or _prompt_text("Base box", DEFAULT_BOX, interactive)
    version = args.wazuh_version or _prompt_text(
        "Wazuh version", DEFAULT_WAZUH_VERSION, interactive
    )
    if topology == TOPOLOGY_AIO:
        indexers, servers = 1, 1
    else:
        indexers = (
            args.indexers
            if args.indexers is not None
            else _prompt_int("Indexer nodes", 3, interactive)
        )
        servers = (
            args.servers
            if args.servers is not None
            else _prompt_int("Wazuh server nodes", 1, interactive)
        )
    deployment = create_deployment(
        project=args.project,
        topology=topology,
        provider=provider,
        box=box,
        wazuh_version=version,
        network=args.network,
        ip_start=args.ip_start,
        indexers=indexers,
        servers=servers,
        dashboards=1,
        cpus=args.cpus,
        memory_mb=args.memory,
        ignore_hardware_check=args.ignore_hardware_check,
    )
    config_path, vagrantfile = initialise_project(
        args.project_dir, deployment, force=args.force
    )
    print(f"Created {config_path}")
    print(f"Created {vagrantfile}")
    print(f"Topology: {deployment.topology}")
    print(f"Wazuh version: {deployment.wazuh_version}")
    for node in deployment.nodes:
        print(f"Machine: {node.name} ({node.ip})")
    print("Next: run 'vagruw up' to start the lab and install Wazuh.")
    return 0


def _handle_generate(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    path = manager.generate(force=args.force)
    print(f"Wrote {path}")
    return 0


def _handle_up(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    manager.up(no_install=args.no_install, reprovision=args.reprovision)
    return 0


def _handle_install(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    manager.install(overwrite=args.overwrite, dry_run=args.dry_run)
    return 0


def _handle_halt(args: argparse.Namespace) -> int:
    DeploymentManager(args.project_dir).halt(args.machine)
    return 0


def _handle_destroy(args: argparse.Namespace) -> int:
    if not args.force:
        if not _is_interactive():
            print(
                "Refusing to destroy machines without --force in a non-interactive shell.",
                file=sys.stderr,
            )
            return 1
        answer = input(
            "Destroy every Vagruw machine and its disk? Type 'yes' to continue: "
        ).strip()
        if answer.lower() not in {"yes", "y"}:
            print("Aborted.")
            return 0
    manager = DeploymentManager(args.project_dir)
    manager.destroy(purge=args.purge)
    return 0


def _handle_status(args: argparse.Namespace) -> int:
    DeploymentManager(args.project_dir).status()
    return 0


def _handle_ssh(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    deployment = load_deployment(ProjectPaths(args.project_dir).config)
    if not args.machine:
        print("Available machines:")
        for node in deployment.nodes:
            print(f"{node.name} ({node.short_name}) at {node.ip}")
        return 1
    parts = list(args.remote_command)
    if parts and parts[0] == "--":
        parts = parts[1:]
    command = " ".join(parts).strip() or None
    manager.ssh(args.machine, command)
    return 0


def _handle_verify(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    return 0 if manager.verify() else 1


def _handle_credentials(args: argparse.Namespace) -> int:
    manager = DeploymentManager(args.project_dir)
    text = manager.credentials()
    if args.show:
        print(text, end="" if text.endswith("\n") else "\n")
        return 0
    deployment = manager.deployment
    password = extract_admin_password(text)
    print(f"Credentials file: {manager.paths.credentials} (mode 600)")
    print(f"Dashboard: {deployment.dashboard_url}")
    print("Dashboard user: admin")
    if password:
        print(f"Dashboard password: {password}")
    else:
        print("The admin password was not found in the credentials file.")
    print("Use 'vagruw credentials --show' to print the complete file.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _handle_init(args)
        if args.command == "generate":
            return _handle_generate(args)
        if args.command == "up":
            return _handle_up(args)
        if args.command == "install":
            return _handle_install(args)
        if args.command == "halt":
            return _handle_halt(args)
        if args.command == "destroy":
            return _handle_destroy(args)
        if args.command == "status":
            return _handle_status(args)
        if args.command == "ssh":
            return _handle_ssh(args)
        if args.command == "verify":
            return _handle_verify(args)
        if args.command == "credentials":
            return _handle_credentials(args)
        parser.error(f"Unknown command: {args.command}")
    except (
        ConfigError,
        OrchestrationError,
        FileExistsError,
        CommandError,
        KeyError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
