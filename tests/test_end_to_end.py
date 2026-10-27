"""End-to-end CLI test with a simulated Vagrant provider.

The test exercises the same code path as a real run: init writes the project,
up calls vagrant, install uploads the pinned installer, runs the assisted
installer commands over SSH, fetches the archive, and extracts credentials.
Only the external vagrant binary and the download are replaced with local fakes.
"""

from __future__ import annotations

import os

from cli import main


def test_full_distributed_lifecycle_with_fake_vagrant(
    tmp_path,
    monkeypatch,
    capsys,
    fake_vagrant,
    fake_installer,
    credentials_archive,
):
    bin_dir, log = fake_vagrant
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("VAGRUW_FAKE_LOG", str(log))
    monkeypatch.setenv("VAGRUW_FAKE_ARCHIVE", str(credentials_archive))
    monkeypatch.setenv("VAGRUW_INSTALLER_SOURCE", str(fake_installer))

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
                "--project",
                "e2e",
            ]
        )
        == 0
    )
    assert main(["-C", str(tmp_path), "up"]) == 0
    output = capsys.readouterr().out
    assert "Wazuh 4.14.9 installation finished." in output
    assert "https://192.168.56.30/" in output

    credentials = tmp_path / ".vagruw" / "credentials.txt"
    assert credentials.exists()
    assert "LabSecret123!" in credentials.read_text()
    assert (tmp_path / ".vagruw" / "wazuh-install-files.tar").exists()
    assert (tmp_path / ".vagruw" / "config.yml").exists()

    commands = log.read_text().splitlines()
    assert commands[0] == "up --provider virtualbox"
    assert any(
        "vagrant upload" not in command and "upload" in command for command in commands
    )
    indexer_two = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-indexer e2e-indexer-2" in command
    )
    start_cluster = next(
        index for index, command in enumerate(commands) if "--start-cluster" in command
    )
    master = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-server e2e-server-1" in command
    )
    dashboard = next(
        index
        for index, command in enumerate(commands)
        if "--wazuh-dashboard e2e-dashboard-1" in command
    )
    assert indexer_two < start_cluster < master < dashboard
    assert any("--generate-config-files" in command for command in commands)
    assert any("chmod 700 /tmp/vagruw" in command for command in commands)
    assert len([command for command in commands if "base64 -w0" in command]) == 1

    assert main(["-C", str(tmp_path), "credentials"]) == 0
    credentials_output = capsys.readouterr().out
    assert "admin" in credentials_output
    assert "LabSecret123!" in credentials_output

    assert main(["-C", str(tmp_path), "halt"]) == 0
    assert main(["-C", str(tmp_path), "status"]) == 0
    assert main(["-C", str(tmp_path), "destroy", "--force", "--purge"]) == 0
    assert not (tmp_path / ".vagruw").exists()
    assert "destroy -f" in log.read_text().splitlines()
