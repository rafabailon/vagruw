"""Installation planning, execution, and lifecycle tests."""

from __future__ import annotations

import base64
import stat

import pytest
from conftest import RecordingRunner

from config import save_deployment
from orchestrator import (
    DeploymentManager,
    FetchAction,
    OrchestrationError,
    SshAction,
    UploadAction,
    build_install_plan,
    decode_base64_output,
    extract_credentials,
    format_action,
    initialise_project,
)
from wazuh import profile_for


def _manager(tmp_path, runner=None, installer_source=None):
    return DeploymentManager(
        tmp_path,
        runner=runner or RecordingRunner(),
        installer_source=installer_source,
    )


def test_aio_plan_uploads_installer_then_installs_then_fetches(
    aio_deployment, tmp_path
):
    profile = profile_for()
    actions = build_install_plan(
        aio_deployment,
        profile,
        tmp_path / "installer.sh",
        tmp_path / "config.yml",
        tmp_path / "archive.tar",
    )
    assert [type(action) for action in actions] == [
        UploadAction,
        SshAction,
        FetchAction,
        SshAction,
    ]
    assert actions[0].remote == "/tmp/vagruw/wazuh-install.sh"
    assert "-a" in actions[1].command
    assert actions[2].remote.endswith("wazuh-install-files.tar")
    assert actions[3].command == "sudo -n rm -rf /tmp/vagruw"


def test_distributed_plan_orders_cluster_initialisation_correctly(
    distributed_deployment, tmp_path
):
    actions = build_install_plan(
        distributed_deployment,
        profile_for(),
        tmp_path / "installer.sh",
        tmp_path / "config.yml",
        tmp_path / "archive.tar",
    )
    commands = [action.command for action in actions if isinstance(action, SshAction)]
    indexer_commands = [command for command in commands if "--wazuh-indexer" in command]
    server_commands = [command for command in commands if "--wazuh-server" in command]
    start_index = next(
        index for index, command in enumerate(commands) if "--start-cluster" in command
    )
    dashboard_index = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-dashboard" in command
    )
    assert len(indexer_commands) == 3
    assert len(server_commands) == 2
    assert commands.index(indexer_commands[-1]) < start_index
    assert start_index < commands.index(server_commands[0])
    assert commands.index(server_commands[-1]) < dashboard_index
    assert "master" not in commands[0]
    cleanup_commands = [
        command for command in commands if "rm -rf /tmp/vagruw" in command
    ]
    assert len(cleanup_commands) == len(distributed_deployment.nodes)
    assert commands[-1] == "sudo -n rm -rf /tmp/vagruw"


def test_distributed_plan_includes_config_and_archive_uploads(
    distributed_deployment, tmp_path
):
    actions = build_install_plan(
        distributed_deployment,
        profile_for(),
        tmp_path / "installer.sh",
        tmp_path / "config.yml",
        tmp_path / "archive.tar",
    )
    uploads = [action for action in actions if isinstance(action, UploadAction)]
    assert any(action.remote.endswith("config.yml") for action in uploads)
    archive_uploads = [
        action for action in uploads if action.local.name == "archive.tar"
    ]
    assert len(archive_uploads) == len(distributed_deployment.nodes)
    archive_cleanups = [
        action
        for action in actions
        if isinstance(action, SshAction) and "rm -f" in action.command
    ]
    assert len(archive_cleanups) == len(distributed_deployment.nodes)


def test_overwrite_is_propagated_to_component_commands(
    distributed_deployment, tmp_path
):
    actions = build_install_plan(
        distributed_deployment,
        profile_for(),
        tmp_path / "installer.sh",
        tmp_path / "config.yml",
        tmp_path / "archive.tar",
        overwrite=True,
    )
    component_commands = [
        action.command
        for action in actions
        if isinstance(action, SshAction) and "--wazuh-" in action.command
    ]
    start_commands = [
        action.command
        for action in actions
        if isinstance(action, SshAction) and "--start-cluster" in action.command
    ]
    assert all("-o" in command for command in component_commands)
    assert all("-o" not in command for command in start_commands)


def test_format_action_describes_each_action_type(tmp_path):
    upload = UploadAction(tmp_path / "a", "/tmp/b", "machine", "upload")
    fetch = FetchAction("machine", "/tmp/b", tmp_path / "a", "fetch")
    ssh = SshAction("machine", "true", "ssh")
    assert "upload" in format_action(upload, 1, 3)
    assert "fetch" in format_action(fetch, 2, 3)
    assert "machine$ true" in format_action(ssh, 3, 3)


def test_decode_base64_ignores_vagrant_prefixes(credentials_archive):
    encoded = base64.b64encode(credentials_archive.read_bytes()).decode()
    output = f"==> machine: transferring archive\n{encoded}\n"
    assert decode_base64_output(output) == credentials_archive.read_bytes()


def test_decode_base64_rejects_invalid_payload():
    with pytest.raises(OrchestrationError, match="valid base64"):
        decode_base64_output("not base64!")


def test_extract_credentials_writes_private_file(tmp_path, credentials_archive):
    destination = tmp_path / "credentials.txt"
    text = extract_credentials(credentials_archive, destination)
    assert "LabSecret123!" in text
    assert destination.read_text() == text
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_extract_credentials_rejects_archive_without_passwords(
    tmp_path, credentials_archive
):
    import tarfile

    empty = tmp_path / "empty.tar"
    with tarfile.open(empty, "w"):
        pass
    with pytest.raises(OrchestrationError, match="does not contain"):
        extract_credentials(empty, tmp_path / "credentials.txt")


def test_ensure_installer_copies_and_verifies_source(tmp_path, fake_installer):
    manager = _manager(tmp_path, installer_source=fake_installer)
    path = manager.ensure_installer(profile_for())
    assert path.exists()
    assert 'wazuh_version="4.14.9"' in path.read_text()
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_ensure_installer_reuses_verified_cache(tmp_path, fake_installer):
    manager = _manager(tmp_path, installer_source=fake_installer)
    first = manager.ensure_installer(profile_for())
    first_mtime = first.stat().st_mtime_ns
    second = manager.ensure_installer(profile_for())
    assert second == first
    assert second.stat().st_mtime_ns == first_mtime


def test_ensure_installer_rejects_version_mismatch(tmp_path):
    wrong = tmp_path / "wrong.sh"
    wrong.write_text(
        'readonly wazuh_major="4.14"\nreadonly wazuh_version="4.14.8"\n',
        encoding="utf-8",
    )
    manager = _manager(tmp_path, installer_source=wrong)
    with pytest.raises(Exception) as error:
        manager.ensure_installer(profile_for())
    assert "4.14.8" in str(error.value)


def test_missing_installer_source_is_reported(tmp_path):
    manager = _manager(tmp_path, installer_source=tmp_path / "missing.sh")
    with pytest.raises(OrchestrationError, match="does not exist"):
        manager.ensure_installer(profile_for())


def test_install_dry_run_does_not_execute_anything(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    runner = RecordingRunner()
    manager = _manager(tmp_path, runner=runner)
    manager.install(dry_run=True)
    assert runner.calls == []
    assert not manager.paths.runtime.exists()


def test_install_dry_run_does_not_create_files(tmp_path, aio_deployment):
    save_deployment(tmp_path / "vagruw.json", aio_deployment)
    manager = _manager(tmp_path)
    manager.install(dry_run=True)
    assert not manager.paths.vagrantfile.exists()
    assert not manager.paths.runtime.exists()


def test_aio_install_executes_plan_and_extracts_credentials(
    tmp_path,
    aio_deployment,
    fake_installer,
    credentials_archive,
    archive_base64,
):
    initialise_project(tmp_path, aio_deployment)
    runner = RecordingRunner(
        stdout_for=lambda args: archive_base64 if "base64 -w0" in " ".join(args) else ""
    )
    manager = _manager(tmp_path, runner=runner, installer_source=fake_installer)
    manager.install()
    commands = runner.commands()
    assert any("vagrant upload" in command for command in commands)
    assert any("wazuh-install.sh -a -i" in command for command in commands)
    assert any("base64 -w0" in command for command in commands)
    assert "LabSecret123!" in manager.credentials()
    assert manager.paths.archive.read_bytes() == credentials_archive.read_bytes()


def test_distributed_install_executes_master_before_worker(
    tmp_path,
    distributed_deployment,
    fake_installer,
    credentials_archive,
    archive_base64,
):
    initialise_project(tmp_path, distributed_deployment)
    runner = RecordingRunner(
        stdout_for=lambda args: archive_base64 if "base64 -w0" in " ".join(args) else ""
    )
    manager = _manager(tmp_path, runner=runner, installer_source=fake_installer)
    manager.install()
    commands = runner.commands()
    master = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-server vagruw-server-1" in command
    )
    worker = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-server vagruw-server-2" in command
    )
    start = next(
        index for index, command in enumerate(commands) if "--start-cluster" in command
    )
    dashboard = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-dashboard" in command
    )
    assert start < master < worker < dashboard
    config_text = manager.paths.remote_config.read_text()
    assert "vagruw-indexer-3" in config_text
    assert "node_type: master" in config_text


def test_up_without_install_starts_all_machines(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    runner = RecordingRunner()
    manager = _manager(tmp_path, runner=runner)
    manager.up(no_install=True)
    assert runner.calls == [["vagrant", "up", "--provider", "virtualbox"]]


def test_up_with_reprovision_adds_the_flag(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    runner = RecordingRunner()
    manager = _manager(tmp_path, runner=runner)
    manager.up(no_install=True, reprovision=True)
    assert runner.calls[0][-1] == "--provision"


def test_halt_status_ssh_and_destroy_commands(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    runner = RecordingRunner()
    manager = _manager(tmp_path, runner=runner)
    manager.halt()
    manager.halt("aio")
    manager.status()
    manager.ssh("aio", "hostname")
    manager.ssh("aio")
    manager.destroy()
    commands = runner.commands()
    assert "vagrant halt" in commands
    assert "vagrant halt vagruw-aio" in commands
    assert "vagrant status" in commands
    assert "vagrant ssh vagruw-aio -c hostname" in commands
    assert "vagrant ssh vagruw-aio" in commands
    assert "vagrant destroy -f" in commands


def test_destroy_purge_removes_runtime(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    manager = _manager(tmp_path)
    manager.paths.ensure_runtime()
    assert manager.paths.runtime.exists()
    manager.destroy(purge=True)
    assert not manager.paths.runtime.exists()


def test_generate_requires_force_to_replace(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    manager = _manager(tmp_path)
    with pytest.raises(FileExistsError):
        manager.generate()
    manager.generate(force=True)


def test_verify_checks_services_and_cluster(
    tmp_path, aio_deployment, credentials_archive
):
    initialise_project(tmp_path, aio_deployment)
    manager = _manager(tmp_path)
    manager.paths.ensure_runtime()
    extract_credentials(credentials_archive, manager.paths.credentials)
    manager.paths.archive.write_bytes(credentials_archive.read_bytes())

    def stdout_for(args):
        command = " ".join(args)
        if "systemctl is-active" in command:
            return (
                "wazuh-indexer=active\nwazuh-manager=active\nwazuh-dashboard=active\n"
            )
        if "_cluster/health" in command:
            return '{"status":"green"}\n'
        return ""

    manager.runner = RecordingRunner(stdout_for=stdout_for)
    assert manager.verify() is True


def test_verify_reports_inactive_service(tmp_path, aio_deployment, credentials_archive):
    initialise_project(tmp_path, aio_deployment)
    manager = _manager(tmp_path)
    manager.paths.ensure_runtime()
    extract_credentials(credentials_archive, manager.paths.credentials)
    manager.runner = RecordingRunner(
        stdout_for=lambda args: (
            "wazuh-indexer=inactive\nwazuh-manager=active\nwazuh-dashboard=active\n"
            if "systemctl is-active" in " ".join(args)
            else '{"status":"green"}'
        )
    )
    assert manager.verify() is False


def test_credentials_missing_has_actionable_error(tmp_path, aio_deployment):
    initialise_project(tmp_path, aio_deployment)
    manager = _manager(tmp_path)
    with pytest.raises(OrchestrationError, match="vagruw install"):
        manager.credentials()


def test_initialise_project_writes_gitignore_and_refuses_overwrite(
    tmp_path, aio_deployment
):
    config_path, vagrantfile = initialise_project(tmp_path, aio_deployment)
    assert config_path.exists() and vagrantfile.exists()
    gitignore = (tmp_path / ".gitignore").read_text()
    assert ".vagruw/" in gitignore
    assert ".vagrant/" in gitignore
    with pytest.raises(FileExistsError):
        initialise_project(tmp_path, aio_deployment)
    initialise_project(tmp_path, aio_deployment, force=True)


def test_project_paths_are_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    manager = DeploymentManager(".")
    assert manager.paths.root == tmp_path.resolve()
    assert str(manager.paths.vagrantfile).startswith(str(tmp_path.resolve()))
