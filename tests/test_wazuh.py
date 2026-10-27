"""Wazuh release profile, command, and credential tests."""

from __future__ import annotations

import shlex

import pytest

from model import ROLE_DASHBOARD, ROLE_INDEXER, ROLE_SERVER
from wazuh import (
    InstallerVersionMismatch,
    UnsupportedWazuhVersion,
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
    verify_installer_text,
)


def test_default_profile_matches_current_stable_release():
    profile = profile_for()
    assert profile.version == "4.14.9"
    assert profile.series == "4.14"
    assert profile.installer_url == "https://packages.wazuh.com/4.14/wazuh-install.sh"
    assert profile.config_key == "server"
    assert profile.server_flag == "--wazuh-server"
    assert profile.installer_filename == "wazuh-install-4.14.9.sh"


def test_other_4x_series_use_the_same_assisted_installer_contract():
    profile = profile_for("4.13.1")
    assert profile.series == "4.13"
    assert profile.installer_url == "https://packages.wazuh.com/4.13/wazuh-install.sh"


@pytest.mark.parametrize("version", ["4.8.0", "5.0.0", "4.14", "latest", ""])
def test_unsupported_versions_are_rejected(version):
    with pytest.raises(UnsupportedWazuhVersion):
        profile_for(version)


def test_installer_text_must_match_the_pinned_version():
    good = 'readonly wazuh_major="4.14"\nreadonly wazuh_version="4.14.9"\n'
    verify_installer_text(good, profile_for("4.14.9"))
    with pytest.raises(InstallerVersionMismatch, match="pins 4.14.8"):
        verify_installer_text(good, profile_for("4.14.8"))


def test_installer_text_must_look_like_an_installer():
    with pytest.raises(InstallerVersionMismatch, match="does not look like"):
        verify_installer_text("<html>not an installer</html>", profile_for())


def test_installer_series_must_match():
    text = 'readonly wazuh_major="4.13"\nreadonly wazuh_version="4.14.9"\n'
    with pytest.raises(InstallerVersionMismatch, match="release series"):
        verify_installer_text(text, profile_for())


def test_aio_configuration_reuses_one_address_for_all_components(aio_deployment):
    yaml = render_config_yaml(aio_deployment, profile_for())
    assert "indexer:" in yaml
    assert "server:" in yaml
    assert "dashboard:" in yaml
    assert yaml.count("192.168.56.10") == 3
    assert "vagruw-aio" in yaml
    assert "node_type" not in yaml


def test_distributed_configuration_contains_master_and_workers(distributed_deployment):
    yaml = render_config_yaml(distributed_deployment, profile_for())
    assert "  indexer:" in yaml
    assert "  server:" in yaml
    assert "  dashboard:" in yaml
    assert "node_type: master" in yaml
    assert "node_type: worker" in yaml
    assert "vagruw-server-1" in yaml
    assert "192.168.56.30" in yaml


def test_single_server_distribution_omits_node_type():
    from config import create_deployment

    deployment = create_deployment(topology="distributed", servers=1)
    yaml = render_config_yaml(deployment, profile_for())
    assert "node_type" not in yaml


def test_aio_install_command_includes_lab_flags():
    profile = profile_for()
    command = all_in_one_command(profile, ignore_hardware_check=True)
    assert command.endswith("wazuh-install.sh -a -i")
    assert "sudo -n bash" in command
    assert "DEBIAN_FRONTEND=noninteractive" in command


def test_overwrite_flag_is_added_for_component_install():
    profile = profile_for()
    command = component_command(
        profile,
        "vagruw-indexer-1",
        ROLE_INDEXER,
        ignore_hardware_check=False,
        overwrite=True,
    )
    assert command.endswith("--wazuh-indexer vagruw-indexer-1 -o")


@pytest.mark.parametrize(
    ("role", "flag"),
    [
        (ROLE_INDEXER, "--wazuh-indexer"),
        (ROLE_SERVER, "--wazuh-server"),
        (ROLE_DASHBOARD, "--wazuh-dashboard"),
    ],
)
def test_component_commands_use_role_specific_flags(role, flag):
    command = component_command(
        profile_for(), "node-1", role, ignore_hardware_check=True
    )
    assert f"{flag} node-1" in command


def test_unknown_component_role_is_rejected():
    with pytest.raises(ValueError, match="no distributed installer command"):
        component_command(profile_for(), "node-1", "agent", ignore_hardware_check=True)


def test_generate_and_start_cluster_commands():
    profile = profile_for()
    assert generate_config_command(profile).endswith("--generate-config-files")
    assert start_cluster_command(profile).endswith("--start-cluster")


def test_cluster_health_command_quotes_the_password():
    password = "secret with spaces!'"
    command = cluster_health_command(password)
    assert "sudo -n curl" in command
    assert shlex.quote(f"admin:{password}") in command
    assert "_cluster/health" in command


def test_cleanup_command_removes_remote_install_directory():
    assert cleanup_command() == "sudo -n rm -rf /tmp/vagruw"


def test_service_check_command_lists_every_service():
    command = service_check_command(("wazuh-indexer", "wazuh-manager"))
    assert "for service in wazuh-indexer wazuh-manager" in command
    assert "systemctl is-active" in command


def test_admin_password_extraction_from_current_password_file():
    text = (
        "# Admin user\n"
        "  indexer_username: 'admin'\n"
        "  indexer_password: 'S3cret!'\n"
        "\n"
        "# Indexer user\n"
        "  indexer_username: 'kibanaserver'\n"
        "  indexer_password: 'AnotherSecret'\n"
    )
    assert extract_admin_password(text) == "S3cret!"


def test_admin_password_extraction_accepts_legacy_quoted_listing():
    text = "header\n'admin' password: 'S3cret!'\n'other' password: 'x'\n"
    assert extract_admin_password(text) == "S3cret!"


def test_admin_password_extraction_returns_none_without_admin():
    text = "  indexer_username: 'kibanaserver'\n  indexer_password: 'x'\n"
    assert extract_admin_password(text) is None
    assert extract_admin_password("no password here") is None
