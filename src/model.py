"""Domain objects shared by configuration, generation, and orchestration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

ROLE_AIO = "aio"
ROLE_INDEXER = "indexer"
ROLE_SERVER = "server"
ROLE_DASHBOARD = "dashboard"

TOPOLOGY_AIO = "aio"
TOPOLOGY_DISTRIBUTED = "distributed"

PROVIDER_VIRTUALBOX = "virtualbox"
PROVIDER_LIBVIRT = "libvirt"

SERVICE_BY_ROLE = {
    ROLE_INDEXER: "wazuh-indexer",
    ROLE_SERVER: "wazuh-manager",
    ROLE_DASHBOARD: "wazuh-dashboard",
}


@dataclass(frozen=True)
class Node:
    """A single virtual machine and the Wazuh component it hosts."""

    name: str
    role: str
    ip: str
    cpus: int
    memory_mb: int
    node_type: str | None = None

    @property
    def short_name(self) -> str:
        """Return the role-oriented name used on the command line."""
        if self.role == ROLE_AIO:
            return ROLE_AIO
        suffix = self.name.rsplit("-", 1)[-1]
        return f"{self.role}-{suffix}"

    @property
    def services(self) -> tuple[str, ...]:
        """Return the systemd services that should be active on this node."""
        if self.role == ROLE_AIO:
            return ("wazuh-indexer", "wazuh-manager", "wazuh-dashboard")
        service = SERVICE_BY_ROLE.get(self.role)
        return (service,) if service else ()


@dataclass(frozen=True)
class Deployment:
    """A complete, validated description of one Vagruw deployment."""

    project: str
    topology: str
    provider: str
    box: str
    wazuh_version: str
    network: str
    ip_start: int
    indexers: int
    servers: int
    dashboards: int
    resources: dict[str, dict[str, int]]
    ignore_hardware_check: bool
    nodes: tuple[Node, ...]

    @property
    def is_aio(self) -> bool:
        """Return True when every Wazuh component runs on one machine."""
        return self.topology == TOPOLOGY_AIO

    @property
    def machine_names(self) -> tuple[str, ...]:
        """Return every machine name in creation order."""
        return tuple(node.name for node in self.nodes)

    @property
    def indexer_nodes(self) -> tuple[Node, ...]:
        """Return the indexer nodes in configuration order."""
        return self.nodes_by_role(ROLE_INDEXER)

    @property
    def server_nodes(self) -> tuple[Node, ...]:
        """Return the Wazuh server nodes with the master first."""
        return self.nodes_by_role(ROLE_SERVER)

    @property
    def dashboard_nodes(self) -> tuple[Node, ...]:
        """Return the dashboard nodes."""
        return self.nodes_by_role(ROLE_DASHBOARD)

    @property
    def aio_node(self) -> Node | None:
        """Return the all-in-one node when that topology is selected."""
        for node in self.nodes:
            if node.role == ROLE_AIO:
                return node
        return None

    @property
    def control_node(self) -> Node:
        """Return the node that generates certificates and passwords."""
        if self.is_aio:
            node = self.aio_node
            if node is None:
                raise ValueError("The all-in-one topology has no node.")
            return node
        if not self.indexer_nodes:
            raise ValueError("The distributed topology has no indexer node.")
        return self.indexer_nodes[0]

    @property
    def dashboard(self) -> Node:
        """Return the node that serves the Wazuh dashboard."""
        if self.is_aio:
            node = self.aio_node
            if node is None:
                raise ValueError("The all-in-one topology has no node.")
            return node
        if not self.dashboard_nodes:
            raise ValueError("The distributed topology has no dashboard node.")
        return self.dashboard_nodes[0]

    @property
    def dashboard_url(self) -> str:
        """Return the default dashboard URL."""
        return f"https://{self.dashboard.ip}/"

    def nodes_by_role(self, role: str) -> tuple[Node, ...]:
        """Return all nodes for a role while preserving their order."""
        return tuple(node for node in self.nodes if node.role == role)

    def node(self, name_or_short_name: str) -> Node:
        """Resolve a full machine name or a short role name such as indexer-2."""
        for node in self.nodes:
            if name_or_short_name in {node.name, node.short_name}:
                return node
        choices = ", ".join(self.machine_names)
        raise KeyError(
            f"Unknown machine '{name_or_short_name}'. Valid machines: {choices}."
        )

    def resource_for(self, role: str) -> dict[str, int]:
        """Return the CPU and memory profile for a role."""
        return dict(self.resources[role])

    def hosts_entries(self) -> Iterable[str]:
        """Yield /etc/hosts lines for every machine in the lab."""
        for node in self.nodes:
            yield f"{node.ip} {node.name}"
