"""Configuration and topology validation tests."""

from __future__ import annotations

import json

import pytest

from config import (
    DEFAULT_BOX,
    DEFAULT_NETWORK,
    DEFAULT_RESOURCES,
    ConfigError,
    create_deployment,
    default_config,
    deployment_from_dict,
    deployment_to_dict,
    load_deployment,
    save_deployment,
)
from model import ROLE_AIO, ROLE_DASHBOARD, ROLE_INDEXER, ROLE_SERVER


def test_default_configuration_is_aio():
    deployment = deployment_from_dict(default_config())
    assert deployment.topology == "aio"
    assert deployment.machine_names == ("vagruw-aio",)
    assert deployment.aio_node.role == ROLE_AIO
    assert deployment.aio_node.ip == "192.168.56.10"
    assert deployment.dashboard_url == "https://192.168.56.10/"
    assert deployment.wazuh_version == "4.14.9"
    assert deployment.box == DEFAULT_BOX
    assert deployment.network == DEFAULT_NETWORK


def test_create_aio_ignores_distributed_counts():
    deployment = create_deployment(topology="aio", indexers=5, servers=4)
    assert deployment.indexers == deployment.servers == deployment.dashboards == 1
    assert len(deployment.nodes) == 1


def test_distributed_node_names_and_addresses():
    deployment = create_deployment(
        topology="distributed",
        indexers=3,
        servers=2,
        project="lab",
    )
    assert deployment.machine_names == (
        "lab-indexer-1",
        "lab-indexer-2",
        "lab-indexer-3",
        "lab-server-1",
        "lab-server-2",
        "lab-dashboard-1",
    )
    assert [node.ip for node in deployment.indexer_nodes] == [
        "192.168.56.10",
        "192.168.56.11",
        "192.168.56.12",
    ]
    assert [node.ip for node in deployment.server_nodes] == [
        "192.168.56.20",
        "192.168.56.21",
    ]
    assert deployment.dashboard.ip == "192.168.56.30"
    assert deployment.control_node.name == "lab-indexer-1"


def test_distributed_server_roles_are_explicit_for_a_cluster():
    deployment = create_deployment(topology="distributed", servers=3)
    assert [node.node_type for node in deployment.server_nodes] == [
        "master",
        "worker",
        "worker",
    ]


def test_single_server_has_no_node_type():
    deployment = create_deployment(topology="distributed", servers=1)
    assert deployment.server_nodes[0].node_type is None


def test_each_role_receives_its_default_resources():
    deployment = create_deployment(topology="distributed", indexers=1, servers=1)
    assert (
        deployment.indexer_nodes[0].memory_mb
        == DEFAULT_RESOURCES[ROLE_INDEXER]["memory_mb"]
    )
    assert (
        deployment.server_nodes[0].memory_mb
        == DEFAULT_RESOURCES[ROLE_SERVER]["memory_mb"]
    )
    assert (
        deployment.dashboard_nodes[0].memory_mb
        == DEFAULT_RESOURCES[ROLE_DASHBOARD]["memory_mb"]
    )


def test_resource_override_applies_to_every_role():
    deployment = create_deployment(topology="distributed", cpus=4, memory_mb=8192)
    assert all(node.cpus == 4 for node in deployment.nodes)
    assert all(node.memory_mb == 8192 for node in deployment.nodes)


def test_custom_network_and_start_offset():
    deployment = create_deployment(
        topology="distributed",
        network="10.20.30.0/24",
        ip_start=50,
        indexers=2,
        servers=1,
    )
    assert [node.ip for node in deployment.indexer_nodes] == [
        "10.20.30.50",
        "10.20.30.51",
    ]
    assert deployment.server_nodes[0].ip == "10.20.30.60"
    assert deployment.dashboard.ip == "10.20.30.70"


def test_configuration_round_trip(tmp_path):
    deployment = create_deployment(
        topology="distributed", indexers=2, servers=2, project="roundtrip"
    )
    path = tmp_path / "vagruw.json"
    save_deployment(path, deployment)
    loaded = load_deployment(path)
    assert loaded == deployment
    assert json.loads(path.read_text())["counts"]["servers"] == 2


def test_serialised_configuration_has_expected_keys(aio_deployment):
    data = deployment_to_dict(aio_deployment)
    assert data["schema_version"] == 1
    assert data["project"] == "vagruw"
    assert data["topology"] == "aio"
    assert data["resources"]["aio"]["memory_mb"] == 4096


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("topology", "cluster", "topology"),
        ("provider", "vmware", "provider"),
        ("box", "ubuntu/jammy64", "generic image"),
        ("project", "Bad Project", "project"),
        ("network", "not-a-network", "network"),
        ("wazuh_version", "5.0.0", "Wazuh"),
        ("ignore_hardware_check", "yes", "true or false"),
    ],
)
def test_invalid_top_level_values_are_rejected(field, value, message):
    data = default_config()
    data[field] = value
    with pytest.raises(ConfigError, match=message):
        deployment_from_dict(data)


def test_unknown_schema_version_is_rejected():
    data = default_config()
    data["schema_version"] = 99
    with pytest.raises(ConfigError, match="schema_version"):
        deployment_from_dict(data)


def test_unknown_top_level_field_is_rejected():
    data = default_config()
    data["toplogy"] = "distributed"
    with pytest.raises(ConfigError, match="Unknown configuration fields: toplogy"):
        deployment_from_dict(data)


def test_zero_indexers_is_rejected():
    data = default_config()
    data["topology"] = "distributed"
    data["counts"] = {"indexers": 0, "servers": 1, "dashboards": 1}
    with pytest.raises(ConfigError, match="counts.indexers"):
        deployment_from_dict(data)


def test_too_many_indexers_is_rejected():
    data = default_config()
    data["topology"] = "distributed"
    data["counts"] = {"indexers": 10, "servers": 1, "dashboards": 1}
    with pytest.raises(ConfigError, match="must not exceed"):
        deployment_from_dict(data)


def test_multiple_dashboards_are_rejected():
    data = default_config()
    data["topology"] = "distributed"
    data["counts"] = {"indexers": 1, "servers": 1, "dashboards": 2}
    with pytest.raises(ConfigError, match="exactly one Wazuh dashboard"):
        deployment_from_dict(data)


def test_aio_rejects_multiple_machines():
    data = default_config()
    data["counts"] = {"indexers": 2, "servers": 1, "dashboards": 1}
    with pytest.raises(ConfigError, match="exactly one machine"):
        deployment_from_dict(data)


def test_too_small_network_is_rejected():
    data = default_config()
    data["network"] = "192.168.56.0/30"
    with pytest.raises(ConfigError, match="eight addresses"):
        deployment_from_dict(data)


def test_public_network_is_rejected():
    data = default_config()
    data["network"] = "8.8.8.0/24"
    with pytest.raises(ConfigError, match="private IPv4 network"):
        deployment_from_dict(data)


def test_network_without_room_for_role_offsets_is_rejected():
    data = default_config()
    data["topology"] = "distributed"
    data["network"] = "192.168.56.0/28"
    data["ip_start"] = 10
    with pytest.raises(ConfigError, match="no room"):
        deployment_from_dict(data)


def test_invalid_resources_are_rejected():
    data = default_config()
    data["resources"]["aio"]["memory_mb"] = 512
    with pytest.raises(ConfigError, match="memory_mb"):
        deployment_from_dict(data)


def test_unknown_resource_role_is_rejected():
    data = default_config()
    data["resources"]["worker"] = {"cpus": 2, "memory_mb": 2048}
    with pytest.raises(ConfigError, match="Unknown resource roles"):
        deployment_from_dict(data)


def test_missing_configuration_file_has_actionable_error(tmp_path):
    with pytest.raises(ConfigError, match="vagruw init"):
        load_deployment(tmp_path / "missing.json")


def test_invalid_json_has_actionable_error(tmp_path):
    path = tmp_path / "vagruw.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_deployment(path)


def test_node_lookup_accepts_short_names(distributed_deployment):
    assert distributed_deployment.node("indexer-2").name == "vagruw-indexer-2"
    assert distributed_deployment.node("server-1").node_type == "master"
    assert distributed_deployment.node("vagruw-server-2").role == ROLE_SERVER
    with pytest.raises(KeyError, match="Unknown machine"):
        distributed_deployment.node("missing")
