"""Command-line interface tests."""

from __future__ import annotations

import json
import os

from cli import main


def test_init_aio_creates_generated_files(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert (tmp_path / "Vagrantfile").exists()
    data = json.loads((tmp_path / "vagruw.json").read_text())
    assert data["topology"] == "aio"
    assert data["wazuh_version"] == "4.14.9"
    assert "vagruw-aio" in (tmp_path / "Vagrantfile").read_text()
    assert ".vagruw/" in (tmp_path / ".gitignore").read_text()


def test_init_distributed_with_counts(tmp_path):
    assert (
        main(
            [
                "-C",
                str(tmp_path),
                "init",
                "--yes",
                "--topology",
                "distributed",
                "--indexers",
                "2",
                "--servers",
                "2",
                "--box",
                "generic/rocky9",
            ]
        )
        == 0
    )
    data = json.loads((tmp_path / "vagruw.json").read_text())
    assert data["counts"] == {"indexers": 2, "servers": 2, "dashboards": 1}
    text = (tmp_path / "Vagrantfile").read_text()
    assert "vagruw-server-2" in text
    assert "generic/rocky9" in text


def test_init_refuses_overwrite_without_force(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 1
    assert main(["-C", str(tmp_path), "init", "--yes", "--force"]) == 0


def test_init_rejects_invalid_box(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes", "--box", "ubuntu/jammy64"]) == 1
    assert not (tmp_path / "vagruw.json").exists()


def test_init_rejects_zero_node_counts(tmp_path):
    base = ["-C", str(tmp_path), "init", "--yes", "--topology", "distributed"]
    assert main([*base, "--indexers", "0"]) == 1
    assert main([*base, "--servers", "0"]) == 1
    assert not (tmp_path / "vagruw.json").exists()


def test_generate_requires_configuration(tmp_path):
    assert main(["-C", str(tmp_path), "generate"]) == 1


def test_generate_replaces_vagrantfile_with_force(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "generate"]) == 1
    assert main(["-C", str(tmp_path), "generate", "--force"]) == 0


def test_install_dry_run_lists_actions(tmp_path, capsys):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "install", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "Installation plan for Wazuh 4.14.9" in output
    assert "-a -i" in output
    assert "wazuh-install-files.tar" in output


def test_up_requires_configuration(tmp_path):
    assert main(["-C", str(tmp_path), "up", "--no-install"]) == 1


def test_credentials_reports_secret_and_path(tmp_path, capsys):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    runtime = tmp_path / ".vagruw"
    runtime.mkdir()
    credentials = runtime / "credentials.txt"
    credentials.write_text("'admin' password: 'VisibleSecret'\n", encoding="utf-8")
    assert main(["-C", str(tmp_path), "credentials"]) == 0
    output = capsys.readouterr().out
    assert "VisibleSecret" in output
    assert "https://192.168.56.10/" in output
    assert main(["-C", str(tmp_path), "credentials", "--show"]) == 0
    assert "VisibleSecret" in capsys.readouterr().out


def test_credentials_missing_returns_failure(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "credentials"]) == 1


def test_destroy_without_force_is_refused_in_non_interactive_shell(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "destroy"]) == 1


def test_ssh_without_machine_lists_machines(tmp_path, capsys):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "ssh"]) == 1
    output = capsys.readouterr().out
    assert "vagruw-aio" in output
    assert "https" not in output


def test_ssh_unknown_machine_returns_failure(tmp_path):
    assert main(["-C", str(tmp_path), "init", "--yes"]) == 0
    assert main(["-C", str(tmp_path), "ssh", "missing"]) == 1


def test_lifecycle_commands_use_fake_vagrant(
    tmp_path, monkeypatch, fake_vagrant, credentials_archive
):
    bin_dir, log = fake_vagrant
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("VAGRUW_FAKE_LOG", str(log))
    monkeypatch.setenv("VAGRUW_FAKE_ARCHIVE", str(credentials_archive))
    assert (
        main(
            [
                "-C",
                str(tmp_path),
                "init",
                "--yes",
                "--topology",
                "distributed",
                "--indexers",
                "1",
            ]
        )
        == 0
    )

    runtime = tmp_path / ".vagruw"
    runtime.mkdir()
    (runtime / "credentials.txt").write_text(
        "'admin' password: 'Secret'\n", encoding="utf-8"
    )

    assert main(["-C", str(tmp_path), "halt"]) == 0
    assert main(["-C", str(tmp_path), "halt", "--machine", "indexer-1"]) == 0
    assert main(["-C", str(tmp_path), "status"]) == 0
    assert main(["-C", str(tmp_path), "ssh", "indexer-1", "--", "hostname"]) == 0
    assert main(["-C", str(tmp_path), "verify"]) == 0
    assert main(["-C", str(tmp_path), "destroy", "--force", "--purge"]) == 0

    commands = log.read_text().splitlines()
    assert "halt" in commands
    assert "halt vagruw-indexer-1" in commands
    assert "status" in commands
    assert any("ssh vagruw-indexer-1 -c hostname" in command for command in commands)
    assert "destroy -f" in commands
    assert not runtime.exists()
