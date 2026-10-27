"""Configuration validation and deterministic node allocation."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from constants import DEFAULT_WAZUH_VERSION
from model import (
    PROVIDER_LIBVIRT,
    PROVIDER_VIRTUALBOX,
    ROLE_AIO,
    ROLE_DASHBOARD,
    ROLE_INDEXER,
    ROLE_SERVER,
    TOPOLOGY_AIO,
    TOPOLOGY_DISTRIBUTED,
    Deployment,
    Node,
)
from wazuh import UnsupportedWazuhVersion, profile_for

SCHEMA_VERSION = 1
DEFAULT_PROJECT = "vagruw"
DEFAULT_PROVIDER = PROVIDER_VIRTUALBOX
DEFAULT_BOX = "generic/ubuntu2204"
DEFAULT_NETWORK = "192.168.56.0/24"
DEFAULT_IP_START = 10
DEFAULT_INDEXERS = 3
DEFAULT_SERVERS = 1
MAX_INDEXERS = 9
MAX_SERVERS = 9
ROLE_IP_OFFSETS = {
    ROLE_INDEXER: 0,
    ROLE_SERVER: 10,
    ROLE_DASHBOARD: 20,
}
DEFAULT_RESOURCES = {
    ROLE_AIO: {"cpus": 2, "memory_mb": 4096},
    ROLE_INDEXER: {"cpus": 2, "memory_mb": 4096},
    ROLE_SERVER: {"cpus": 2, "memory_mb": 2048},
    ROLE_DASHBOARD: {"cpus": 2, "memory_mb": 2048},
}
PROJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
BOX_PATTERN = re.compile(r"^generic/[a-z0-9][a-z0-9._-]*$")
SUPPORTED_PROVIDERS = (PROVIDER_VIRTUALBOX, PROVIDER_LIBVIRT)


class ConfigError(ValueError):
    """Raised when a Vagruw configuration is missing or invalid."""


def default_config() -> dict[str, Any]:
    """Return a complete all-in-one configuration dictionary."""
    return {
        "schema_version": SCHEMA_VERSION,
        "project": DEFAULT_PROJECT,
        "topology": TOPOLOGY_AIO,
        "provider": DEFAULT_PROVIDER,
        "box": DEFAULT_BOX,
        "wazuh_version": DEFAULT_WAZUH_VERSION,
        "network": DEFAULT_NETWORK,
        "ip_start": DEFAULT_IP_START,
        "counts": {"indexers": 1, "servers": 1, "dashboards": 1},
        "resources": {role: dict(values) for role, values in DEFAULT_RESOURCES.items()},
        "ignore_hardware_check": True,
    }


def _as_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"The '{field}' field must be a JSON object.")
    return value


def _as_positive_int(value: Any, field: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"The '{field}' field must be an integer.")
    if value < minimum:
        raise ConfigError(f"The '{field}' field must be at least {minimum}.")
    return value


def _normalise_resources(raw: Any) -> dict[str, dict[str, int]]:
    resources = {role: dict(values) for role, values in DEFAULT_RESOURCES.items()}
    if raw is None:
        return resources
    supplied = _as_mapping(raw, "resources")
    for role in (ROLE_AIO, ROLE_INDEXER, ROLE_SERVER, ROLE_DASHBOARD):
        if role not in supplied:
            continue
        values = _as_mapping(supplied[role], f"resources.{role}")
        cpus = _as_positive_int(
            values.get("cpus", resources[role]["cpus"]), f"resources.{role}.cpus"
        )
        memory = _as_positive_int(
            values.get("memory_mb", resources[role]["memory_mb"]),
            f"resources.{role}.memory_mb",
            1024,
        )
        if memory > 65536:
            raise ConfigError(
                f"The 'resources.{role}.memory_mb' value must not exceed 65536."
            )
        if cpus > 64:
            raise ConfigError(f"The 'resources.{role}.cpus' value must not exceed 64.")
        resources[role] = {"cpus": cpus, "memory_mb": memory}
    unknown = set(supplied) - {ROLE_AIO, ROLE_INDEXER, ROLE_SERVER, ROLE_DASHBOARD}
    if unknown:
        raise ConfigError(f"Unknown resource roles: {', '.join(sorted(unknown))}.")
    return resources


def _validate_counts(
    topology: str,
    raw: Any,
) -> tuple[int, int, int]:
    if topology == TOPOLOGY_AIO:
        counts = {"indexers": 1, "servers": 1, "dashboards": 1}
        if raw is not None:
            supplied = _as_mapping(raw, "counts")
            for key, value in supplied.items():
                if key not in counts:
                    raise ConfigError(f"Unknown count field '{key}'.")
                if value != 1:
                    raise ConfigError(
                        "An all-in-one deployment requires exactly one machine."
                    )
        return 1, 1, 1
    defaults = {
        "indexers": DEFAULT_INDEXERS,
        "servers": DEFAULT_SERVERS,
        "dashboards": 1,
    }
    supplied = _as_mapping(raw, "counts") if raw is not None else {}
    unknown = set(supplied) - set(defaults)
    if unknown:
        raise ConfigError(f"Unknown count fields: {', '.join(sorted(unknown))}.")
    indexers = _as_positive_int(
        supplied.get("indexers", defaults["indexers"]), "counts.indexers"
    )
    servers = _as_positive_int(
        supplied.get("servers", defaults["servers"]), "counts.servers"
    )
    dashboards = _as_positive_int(
        supplied.get("dashboards", defaults["dashboards"]),
        "counts.dashboards",
    )
    if indexers > MAX_INDEXERS:
        raise ConfigError(
            f"The 'counts.indexers' value must not exceed {MAX_INDEXERS}."
        )
    if servers > MAX_SERVERS:
        raise ConfigError(f"The 'counts.servers' value must not exceed {MAX_SERVERS}.")
    if dashboards != 1:
        raise ConfigError("Vagruw currently supports exactly one Wazuh dashboard node.")
    return indexers, servers, dashboards


def _allocate_ip(network: ipaddress.IPv4Network, start: int, offset: int) -> str:
    address_int = int(network.network_address) + start + offset
    if address_int >= int(network.broadcast_address):
        raise ConfigError(
            f"The network {network} has no room for an address at offset {start + offset}."
        )
    address = ipaddress.ip_address(address_int)
    if address not in network:
        raise ConfigError(f"The address {address} is outside the network {network}.")
    return str(address)


def _make_nodes(
    project: str,
    topology: str,
    network_text: str,
    ip_start: int,
    indexers: int,
    servers: int,
    dashboards: int,
    resources: dict[str, dict[str, int]],
) -> tuple[Node, ...]:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError as error:
        raise ConfigError(
            f"The 'network' value is not a valid CIDR: {network_text}."
        ) from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise ConfigError("Vagruw currently supports IPv4 private networks only.")
    if not network.is_private:
        raise ConfigError(
            "The 'network' value must be a private IPv4 network such as 192.168.56.0/24."
        )
    if network.prefixlen > 29:
        raise ConfigError("The lab network must contain at least eight addresses.")
    if not 2 <= ip_start <= 240:
        raise ConfigError("The 'ip_start' value must be between 2 and 240.")
    if topology == TOPOLOGY_AIO:
        role_resource = resources[ROLE_AIO]
        ip = _allocate_ip(network, ip_start, 0)
        return (
            Node(
                name=f"{project}-aio",
                role=ROLE_AIO,
                ip=ip,
                cpus=role_resource["cpus"],
                memory_mb=role_resource["memory_mb"],
            ),
        )
    nodes: list[Node] = []
    for index in range(indexers):
        role_resource = resources[ROLE_INDEXER]
        nodes.append(
            Node(
                name=f"{project}-indexer-{index + 1}",
                role=ROLE_INDEXER,
                ip=_allocate_ip(
                    network, ip_start, ROLE_IP_OFFSETS[ROLE_INDEXER] + index
                ),
                cpus=role_resource["cpus"],
                memory_mb=role_resource["memory_mb"],
            )
        )
    for index in range(servers):
        role_resource = resources[ROLE_SERVER]
        node_type = None
        if servers > 1:
            node_type = "master" if index == 0 else "worker"
        nodes.append(
            Node(
                name=f"{project}-server-{index + 1}",
                role=ROLE_SERVER,
                ip=_allocate_ip(
                    network, ip_start, ROLE_IP_OFFSETS[ROLE_SERVER] + index
                ),
                cpus=role_resource["cpus"],
                memory_mb=role_resource["memory_mb"],
                node_type=node_type,
            )
        )
    for index in range(dashboards):
        role_resource = resources[ROLE_DASHBOARD]
        nodes.append(
            Node(
                name=f"{project}-dashboard-{index + 1}",
                role=ROLE_DASHBOARD,
                ip=_allocate_ip(
                    network, ip_start, ROLE_IP_OFFSETS[ROLE_DASHBOARD] + index
                ),
                cpus=role_resource["cpus"],
                memory_mb=role_resource["memory_mb"],
            )
        )
    return tuple(nodes)


def deployment_from_dict(raw: Mapping[str, Any]) -> Deployment:
    """Validate a configuration mapping and build its complete topology."""
    data = _as_mapping(raw, "configuration")
    allowed_fields = {
        "schema_version",
        "project",
        "topology",
        "provider",
        "box",
        "wazuh_version",
        "network",
        "ip_start",
        "counts",
        "resources",
        "ignore_hardware_check",
    }
    unknown_fields = set(data) - allowed_fields
    if unknown_fields:
        raise ConfigError(
            f"Unknown configuration fields: {', '.join(sorted(unknown_fields))}."
        )
    schema_version = data.get("schema_version", SCHEMA_VERSION)
    if schema_version != SCHEMA_VERSION:
        raise ConfigError(
            f"Unsupported schema_version {schema_version}; expected {SCHEMA_VERSION}."
        )
    project = data.get("project", DEFAULT_PROJECT)
    if not isinstance(project, str) or not PROJECT_PATTERN.match(project):
        raise ConfigError(
            "The 'project' value must use lowercase letters, digits, and hyphens, "
            "and must start with a letter or digit."
        )
    topology = data.get("topology", TOPOLOGY_AIO)
    if topology not in (TOPOLOGY_AIO, TOPOLOGY_DISTRIBUTED):
        raise ConfigError("The 'topology' value must be 'aio' or 'distributed'.")
    provider = data.get("provider", DEFAULT_PROVIDER)
    if provider not in SUPPORTED_PROVIDERS:
        raise ConfigError(
            f"The 'provider' value must be one of: {', '.join(SUPPORTED_PROVIDERS)}."
        )
    box = data.get("box", DEFAULT_BOX)
    if not isinstance(box, str) or not BOX_PATTERN.match(box):
        raise ConfigError(
            "The 'box' value must be a HashiCorp generic image such as generic/ubuntu2204."
        )
    version = data.get("wazuh_version", DEFAULT_WAZUH_VERSION)
    if not isinstance(version, str):
        raise ConfigError("The 'wazuh_version' value must be a string.")
    try:
        profile_for(version)
    except UnsupportedWazuhVersion as error:
        raise ConfigError(str(error)) from error
    network = data.get("network", DEFAULT_NETWORK)
    if not isinstance(network, str):
        raise ConfigError("The 'network' value must be a CIDR string.")
    ip_start = _as_positive_int(data.get("ip_start", DEFAULT_IP_START), "ip_start", 2)
    if ip_start > 240:
        raise ConfigError("The 'ip_start' value must not exceed 240.")
    indexers, servers, dashboards = _validate_counts(topology, data.get("counts"))
    resources = _normalise_resources(data.get("resources"))
    ignore_hardware_check = data.get("ignore_hardware_check", True)
    if not isinstance(ignore_hardware_check, bool):
        raise ConfigError("The 'ignore_hardware_check' value must be true or false.")
    nodes = _make_nodes(
        project,
        topology,
        network,
        ip_start,
        indexers,
        servers,
        dashboards,
        resources,
    )
    return Deployment(
        project=project,
        topology=topology,
        provider=provider,
        box=box,
        wazuh_version=version,
        network=str(ipaddress.ip_network(network, strict=False)),
        ip_start=ip_start,
        indexers=indexers,
        servers=servers,
        dashboards=dashboards,
        resources=resources,
        ignore_hardware_check=ignore_hardware_check,
        nodes=nodes,
    )


def deployment_to_dict(deployment: Deployment) -> dict[str, Any]:
    """Serialise a deployment into the stable on-disk schema."""
    return {
        "schema_version": SCHEMA_VERSION,
        "project": deployment.project,
        "topology": deployment.topology,
        "provider": deployment.provider,
        "box": deployment.box,
        "wazuh_version": deployment.wazuh_version,
        "network": deployment.network,
        "ip_start": deployment.ip_start,
        "counts": {
            "indexers": deployment.indexers,
            "servers": deployment.servers,
            "dashboards": deployment.dashboards,
        },
        "resources": {
            role: dict(values) for role, values in deployment.resources.items()
        },
        "ignore_hardware_check": deployment.ignore_hardware_check,
    }


def create_deployment(
    *,
    project: str = DEFAULT_PROJECT,
    topology: str = TOPOLOGY_AIO,
    provider: str = DEFAULT_PROVIDER,
    box: str = DEFAULT_BOX,
    wazuh_version: str = DEFAULT_WAZUH_VERSION,
    network: str = DEFAULT_NETWORK,
    ip_start: int = DEFAULT_IP_START,
    indexers: int = DEFAULT_INDEXERS,
    servers: int = DEFAULT_SERVERS,
    dashboards: int = 1,
    cpus: int | None = None,
    memory_mb: int | None = None,
    ignore_hardware_check: bool = True,
) -> Deployment:
    """Create a deployment from CLI-oriented values."""
    resources = {role: dict(values) for role, values in DEFAULT_RESOURCES.items()}
    if cpus is not None:
        for values in resources.values():
            values["cpus"] = cpus
    if memory_mb is not None:
        for values in resources.values():
            values["memory_mb"] = memory_mb
    if topology == TOPOLOGY_AIO:
        indexers, servers, dashboards = 1, 1, 1
    data = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "topology": topology,
        "provider": provider,
        "box": box,
        "wazuh_version": wazuh_version,
        "network": network,
        "ip_start": ip_start,
        "counts": {
            "indexers": indexers,
            "servers": servers,
            "dashboards": dashboards,
        },
        "resources": resources,
        "ignore_hardware_check": ignore_hardware_check,
    }
    return deployment_from_dict(data)


def load_deployment(path: str | Path) -> Deployment:
    """Load and validate a vagruw.json file."""
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ConfigError(
            f"Configuration file not found at {config_path}. Run 'vagruw init' first."
        ) from error
    except json.JSONDecodeError as error:
        raise ConfigError(
            f"The configuration file {config_path} is not valid JSON."
        ) from error
    return deployment_from_dict(raw)


def save_deployment(path: str | Path, deployment: Deployment) -> None:
    """Write a deployment as human-editable JSON."""
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        json.dumps(deployment_to_dict(deployment), indent=2) + "\n",
        encoding="utf-8",
    )
