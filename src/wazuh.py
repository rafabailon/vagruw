"""Wazuh version profiles, installer commands, and configuration rendering.

The assisted installation interface is versioned on purpose. A future Wazuh
release may rename a component flag or change the configuration keys, so every
supported release family is described by one explicit profile instead of being
assembled from implicit assumptions.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from constants import DEFAULT_WAZUH_VERSION
from model import ROLE_DASHBOARD, ROLE_INDEXER, ROLE_SERVER, Deployment

REMOTE_DIR = "/tmp/vagruw"
REMOTE_INSTALLER = f"{REMOTE_DIR}/wazuh-install.sh"
REMOTE_CONFIG = f"{REMOTE_DIR}/config.yml"
REMOTE_ARCHIVE = f"{REMOTE_DIR}/wazuh-install-files.tar"

VERSION_PATTERN = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")
INSTALLER_VERSION_PATTERN = re.compile(r'readonly\s+wazuh_version="(?P<version>[^"]+)"')
INSTALLER_MAJOR_PATTERN = re.compile(r'readonly\s+wazuh_major="(?P<series>[^"]+)"')
INDEXER_USERNAME_PATTERN = re.compile(
    r"^\s*indexer_username:\s*['\"]?(?P<username>[^'\"\s]+)['\"]?\s*$"
)
INDEXER_PASSWORD_PATTERN = re.compile(
    r"^\s*indexer_password:\s*['\"]?(?P<password>[^'\"]+)['\"]?\s*$"
)
LEGACY_ADMIN_PASSWORD_PATTERN = re.compile(
    r"^\s*'admin'\s+password:\s*'(?P<password>[^']+)'\s*$"
)


class UnsupportedWazuhVersion(ValueError):
    """Raised when a version cannot be mapped to a verified installer profile."""


class InstallerVersionMismatch(ValueError):
    """Raised when the downloaded installer does not match the pinned version."""


@dataclass(frozen=True)
class WazuhProfile:
    """The installer contract for one Wazuh release series."""

    version: str
    series: str
    installer_url: str
    config_key: str
    indexer_flag: str
    server_flag: str
    dashboard_flag: str
    all_in_one_flag: str
    supports_dependency_flag: bool

    @property
    def installer_filename(self) -> str:
        """Return a stable local filename for the pinned installer."""
        return f"wazuh-install-{self.version}.sh"

    def install_flags(self, ignore_hardware_check: bool, overwrite: bool) -> list[str]:
        """Return common flags accepted by assisted component installation."""
        flags: list[str] = []
        if ignore_hardware_check:
            flags.append("-i")
        if overwrite:
            flags.append("-o")
        return flags


def profile_for(version: str = DEFAULT_WAZUH_VERSION) -> WazuhProfile:
    """Return the installer profile for a Wazuh version.

    Version 4.9 and later use the same assisted-install flags for the central
    components. Version 5 is intentionally rejected until a stable installer
    exists and its renamed server component has been verified.
    """
    match = VERSION_PATTERN.match(version.strip())
    if not match:
        raise UnsupportedWazuhVersion(
            f"Wazuh version '{version}' is not a semantic version such as 4.14.9."
        )
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    if major != 4 or minor < 9:
        raise UnsupportedWazuhVersion(
            "Vagruw currently supports verified Wazuh 4.x installers from 4.9 onward. "
            "Add a new profile in src/wazuh.py before using another release family."
        )
    series = f"{major}.{minor}"
    return WazuhProfile(
        version=version.strip(),
        series=series,
        installer_url=f"https://packages.wazuh.com/{series}/wazuh-install.sh",
        config_key="server",
        indexer_flag="--wazuh-indexer",
        server_flag="--wazuh-server",
        dashboard_flag="--wazuh-dashboard",
        all_in_one_flag="-a",
        supports_dependency_flag=False,
    )


def verify_installer_text(text: str, profile: WazuhProfile) -> None:
    """Validate that an installer script advertises the pinned release."""
    version_match = INSTALLER_VERSION_PATTERN.search(text)
    if version_match is None:
        raise InstallerVersionMismatch(
            "The downloaded file does not look like a Wazuh installation assistant."
        )
    actual_version = version_match.group("version")
    if actual_version != profile.version:
        raise InstallerVersionMismatch(
            f"The Wazuh {profile.series} installer currently publishes {actual_version}, "
            f"but the configuration pins {profile.version}. Use {actual_version}, or update "
            "the pinned version after reviewing the release notes."
        )
    major_match = INSTALLER_MAJOR_PATTERN.search(text)
    if major_match is not None and major_match.group("series") != profile.series:
        raise InstallerVersionMismatch(
            f"The installer reports release series {major_match.group('series')}, "
            f"but {profile.series} was expected."
        )


def verify_installer_file(path: str, profile: WazuhProfile) -> None:
    """Read an installer file and validate its embedded release metadata."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        verify_installer_text(handle.read(131072), profile)


def render_config_yaml(deployment: Deployment, profile: WazuhProfile) -> str:
    """Render the config.yml consumed by the Wazuh assisted installer."""
    lines = [
        f"# Generated by Vagruw for Wazuh {profile.version}.",
        "# Node names and addresses must match the generated Vagrantfile.",
        "nodes:",
        "  indexer:",
    ]
    for node in deployment.indexer_nodes or (
        (deployment.aio_node,) if deployment.aio_node else ()
    ):
        lines.extend([f"    - name: {node.name}", f"      ip: {node.ip}"])
    if deployment.is_aio:
        node = deployment.aio_node
        lines.extend(
            [
                "  # An all-in-one deployment reuses the same address for every component.",
                "  " + profile.config_key + ":",
                f"    - name: {node.name}",
                f"      ip: {node.ip}",
                "  dashboard:",
                f"    - name: {node.name}",
                f"      ip: {node.ip}",
            ]
        )
    else:
        lines.append(f"  {profile.config_key}:")
        for node in deployment.server_nodes:
            lines.append(f"    - name: {node.name}")
            lines.append(f"      ip: {node.ip}")
            if node.node_type is not None:
                lines.append(f"      node_type: {node.node_type}")
        lines.append("  dashboard:")
        for node in deployment.dashboard_nodes:
            lines.append(f"    - name: {node.name}")
            lines.append(f"      ip: {node.ip}")
    return "\n".join(lines) + "\n"


def _shell_prefix() -> str:
    """Return the remote shell prefix used for privileged installer calls."""
    return (
        "export DEBIAN_FRONTEND=noninteractive; "
        f"cd {REMOTE_DIR} && sudo -n bash wazuh-install.sh"
    )


def generate_config_command(profile: WazuhProfile) -> str:
    """Return the command that creates the certificate and password archive."""
    return f"{_shell_prefix()} --generate-config-files"


def all_in_one_command(
    profile: WazuhProfile,
    ignore_hardware_check: bool,
    overwrite: bool = False,
) -> str:
    """Return the command that installs every component on one host."""
    flags = [
        profile.all_in_one_flag,
        *profile.install_flags(ignore_hardware_check, overwrite),
    ]
    return f"{_shell_prefix()} {' '.join(flags)}"


def component_command(
    profile: WazuhProfile,
    node_name: str,
    role: str,
    ignore_hardware_check: bool,
    overwrite: bool = False,
) -> str:
    """Return an assisted-install command for one distributed component."""
    flags = {
        ROLE_INDEXER: profile.indexer_flag,
        ROLE_SERVER: profile.server_flag,
        ROLE_DASHBOARD: profile.dashboard_flag,
    }.get(role)
    if flags is None:
        raise ValueError(f"Role '{role}' has no distributed installer command.")
    arguments = [
        flags,
        node_name,
        *profile.install_flags(ignore_hardware_check, overwrite),
    ]
    return f"{_shell_prefix()} {' '.join(arguments)}"


def start_cluster_command(profile: WazuhProfile) -> str:
    """Return the command that initializes indexer security settings once."""
    return f"{_shell_prefix()} --start-cluster"


def service_check_command(services: tuple[str, ...]) -> str:
    """Return a command that prints one systemd state per requested service."""
    quoted = " ".join(services)
    return f'for service in {quoted}; do printf \'%s=\' "$service"; sudo -n systemctl is-active "$service" || true; done'


def cluster_health_command(password: str) -> str:
    """Return a local indexer health check that uses the admin credentials."""
    credentials = shlex.quote(f"admin:{password}")
    return (
        "sudo -n curl -sk --max-time 15 -u "
        f"{credentials} 'https://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=30s'"
    )


def cleanup_command() -> str:
    """Return the command that removes installer files and credentials from a node."""
    return f"sudo -n rm -rf {shlex.quote(REMOTE_DIR)}"


def extract_admin_password(credentials_text: str) -> str | None:
    """Extract the Wazuh indexer admin password from the password listing.

    Wazuh 4.x writes a YAML-like wazuh-passwords.txt file in which a username
    line is followed by its password line. The parser also accepts the older
    quoted ``'admin' password: '...'`` representation so projects created with
    earlier Vagruw releases remain readable.
    """
    current_username: str | None = None
    for line in credentials_text.splitlines():
        username_match = INDEXER_USERNAME_PATTERN.match(line)
        if username_match is not None:
            current_username = username_match.group("username")
            continue
        password_match = INDEXER_PASSWORD_PATTERN.match(line)
        if password_match is not None and current_username == "admin":
            return password_match.group("password")
        legacy_match = LEGACY_ADMIN_PASSWORD_PATTERN.match(line)
        if legacy_match is not None:
            return legacy_match.group("password")
    return None
