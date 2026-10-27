"""Vagrantfile and bootstrap rendering tests."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from generator import render_bootstrap, render_vagrantfile


def test_vagrantfile_contains_all_distributed_machines(distributed_deployment):
    text = render_vagrantfile(distributed_deployment)
    for node in distributed_deployment.nodes:
        assert f'config.vm.define "{node.name}"' in text
        assert f'node.vm.network "private_network", ip: "{node.ip}"' in text
    assert 'config.vm.box = "generic/ubuntu2204"' in text
    assert "Wazuh version: 4.14.9" in text


def test_aio_vagrantfile_defines_one_machine(aio_deployment):
    text = render_vagrantfile(aio_deployment)
    assert text.count("config.vm.define") == 1
    assert "vagruw-aio" in text
    assert "192.168.56.10" in text


def test_generated_vagrantfile_has_no_indentation(distributed_deployment):
    text = render_vagrantfile(distributed_deployment)
    offenders = [
        (number, line)
        for number, line in enumerate(text.splitlines(), start=1)
        if line and line[0].isspace()
    ]
    assert offenders == []


def test_bootstrap_contains_hosts_and_sysctl(aio_deployment):
    script = render_bootstrap(aio_deployment)
    assert "vagruw managed hosts" in script
    assert "vagruw end hosts" in script
    assert "192.168.56.10 vagruw-aio" in script
    assert "vm.max_map_count=262144" in script
    assert (
        "sed -i '/# vagruw managed hosts/,/# vagruw end hosts/d' /etc/hosts" in script
    )
    assert "set -euo pipefail" in script


def test_bootstrap_is_valid_bash(tmp_path, distributed_deployment):
    script = tmp_path / "bootstrap.sh"
    script.write_text(render_bootstrap(distributed_deployment), encoding="utf-8")
    result = subprocess.run(
        ["bash", "-n", str(script)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("ruby") is None, reason="Ruby is not installed")
def test_generated_vagrantfile_has_valid_ruby_syntax(tmp_path, distributed_deployment):
    path = tmp_path / "Vagrantfile"
    path.write_text(render_vagrantfile(distributed_deployment), encoding="utf-8")
    result = subprocess.run(
        ["ruby", "-c", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "Syntax OK" in result.stdout


@pytest.mark.skipif(shutil.which("vagrant") is None, reason="Vagrant is not installed")
def test_generated_vagrantfile_passes_vagrant_validate(
    tmp_path, distributed_deployment
):
    path = tmp_path / "Vagrantfile"
    path.write_text(render_vagrantfile(distributed_deployment), encoding="utf-8")
    result = subprocess.run(
        ["vagrant", "validate"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env={
            "VAGRANT_HOME": str(tmp_path / ".vagrant.d"),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "validated successfully" in (result.stdout + result.stderr).lower()


def test_provider_resources_are_rendered(aio_deployment):
    aio = aio_deployment
    text = render_vagrantfile(aio)
    assert "provider.memory = 4096" in text
    assert "provider.cpus = 2" in text
    assert 'node.vm.provider "virtualbox"' in text
    assert 'node.vm.provider "libvirt"' in text
    assert 'provider.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]' in text


def test_bootstrap_is_privileged_and_synced_folders_are_disabled(aio_deployment):
    text = render_vagrantfile(aio_deployment)
    assert (
        'node.vm.provision "shell", inline: $vagruw_bootstrap, privileged: true' in text
    )
    assert 'config.vm.synced_folder ".", "/vagrant", disabled: true' in text


def test_generation_is_deterministic(distributed_deployment):
    first = render_vagrantfile(distributed_deployment)
    second = render_vagrantfile(distributed_deployment)
    assert first == second
    assert first.endswith("\n")


def test_comment_records_version_and_provider(aio_deployment):
    text = render_vagrantfile(aio_deployment)
    assert "# Wazuh version: 4.14.9" in text
    assert "# Provider: virtualbox" in text
    assert (
        "# Generic images are published through the HashiCorp Vagrant registry." in text
    )
