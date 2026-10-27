# Vagruw

Vagruw creates reproducible Vagrant labs for Wazuh using HashiCorp `generic/` boxes. It writes the Vagrantfile, starts the virtual machines, sends the Wazuh installation assistant commands that match the selected topology, collects the generated credentials, and provides the lifecycle operations needed to stop, inspect, and destroy the lab. The default target is Wazuh 4.14.9 because installer flags, configuration keys, and package layouts are versioned and can change between Wazuh releases.

The generated Vagrantfile is self-contained. Every Ruby statement and every bootstrap shell statement appears at column zero, because Ruby and Bash do not require indentation and the generated artifact is intended to read as a flat, auditable document. The project documentation follows the same rule: prose is continuous, commands are not indented, and lists are avoided in favour of complete sentences.

## What the lab contains

The all-in-one topology creates one machine named `<project>-aio` at the first address in the lab network. The machine runs the Wazuh indexer, the Wazuh server, and the Wazuh dashboard together. The default all-in-one resources are two virtual CPUs and 4096 MB of memory.

The distributed topology creates indexers, Wazuh servers, and one dashboard. Indexer names use `<project>-indexer-<number>`, server names use `<project>-server-<number>`, and the dashboard name uses `<project>-dashboard-1`. Indexer addresses start at `ip_start`, server addresses start ten positions later, and the dashboard address starts twenty positions later. With the default `192.168.56.0/24` network and `ip_start` of 10, three indexers use `192.168.56.10` through `192.168.56.12`, the first server uses `192.168.56.20`, and the dashboard uses `192.168.56.30`. A multi-server deployment marks the first server as the master and every later server as a worker.

The default indexer resources are two virtual CPUs and 4096 MB of memory. The default server and dashboard resources are two virtual CPUs and 2048 MB of memory. Every machine receives an entry in `/etc/hosts`, the `vm.max_map_count=262144` kernel setting required by the Wazuh indexer, and a UTC timezone when the image provides `timedatectl`.

The generated network is a host-only private network. The dashboard is reachable from the host through its private address and is not forwarded to the public interface. The default box is `generic/ubuntu2204`, and other HashiCorp generic images such as `generic/debian12`, `generic/rocky9`, and `generic/alma9` can be selected when their provider support matches the host. The box must exist in the HashiCorp Vagrant registry before `vagrant up` can download it.

## Requirements

The tool requires Python 3.10 or newer and has no runtime dependencies outside the Python standard library. Vagrant 2.4 or newer must be installed and available on `PATH`. A working Vagrant provider is required for the selected provider value. VirtualBox is supported through Vagrant's built-in provider, so installing VirtualBox is sufficient. Libvirt requires the libvirt daemon and the `vagrant-libvirt` plugin. The host also needs enough memory for every machine in the topology, enough disk space for the boxes and Wazuh data, and outbound HTTPS access to the HashiCorp Vagrant registry and the official Wazuh package host.

The default all-in-one lab needs at least 4096 MB of guest memory and two virtual CPUs. The default three-indexer distributed lab needs three indexer machines at 4096 MB each, one server at 2048 MB, and one dashboard at 2048 MB, so plan for roughly 16 GB of guest memory plus provider overhead. The `ignore_hardware_check` setting is enabled by default because virtual machines often report slightly less memory than their configured amount and the Wazuh assistant otherwise refuses to continue below its recommended threshold. Disable it with `--no-ignore-hardware-check` when the host really does meet the Wazuh requirements and a strict check is preferred.

## Installation

Install the project into a virtual environment so the `vagruw` console script is available.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
vagruw --help
```

The root of this repository already contains a validated all-in-one `Vagrantfile` and its `vagruw.json` configuration. The distributed example is in `examples/distributed`. New labs can be created in any empty directory with the `init` command.

```bash
vagruw -C /path/to/lab init
vagruw -C /path/to/lab up
```

Without flags, `init` asks for the topology, provider, box, Wazuh version, and distributed node counts when the terminal is interactive. In a non-interactive environment it uses the all-in-one defaults unless flags are supplied. The `--yes` flag makes the non-interactive intent explicit. The `--force` flag replaces an existing `vagruw.json` and `Vagrantfile`.

An all-in-one lab can be created without prompts.

```bash
vagruw -C /path/to/lab init --yes --topology aio --project wazuh-lab
vagruw -C /path/to/lab up
```

A distributed lab can be created with an explicit number of indexers and Wazuh servers.

```bash
vagruw -C /path/to/lab init --yes --topology distributed --project wazuh-lab --indexers 3 --servers 1
vagruw -C /path/to/lab up
```

The `--wazuh-version` flag accepts a pinned semantic version such as `4.14.9`. The `--box`, `--provider`, `--network`, `--ip-start`, `--cpus`, and `--memory` flags override the corresponding defaults. The `--memory` value is expressed in megabytes. The project name must use lowercase letters, digits, and hyphens and must start with a letter or digit.

The environment variable `VAGRUW_PROJECT` provides a default project directory when `-C` is not supplied. The environment variable `VAGRUW_INSTALLER_SOURCE` points at a local installer script and is useful for offline labs and tests. A local installer is still checked against the pinned Wazuh version before it is used.

## Lifecycle commands

The `up` command creates and starts every machine and then installs Wazuh unless installation is disabled. The `--no-install` flag stops after Vagrant finishes. The `--reprovision` flag asks Vagrant to run the bootstrap provisioner again, which is the right way to refresh `/etc/hosts` after changing the topology.

```bash
vagruw up
vagruw up --no-install
vagruw up --reprovision
vagruw install
vagruw install --dry-run
vagruw install --overwrite
```

The `install` command works on machines that already exist. The `--dry-run` flag prints the ordered uploads and remote commands without touching the filesystem or the machines. The `--overwrite` flag adds the Wazuh assistant's `-o` option to component installs and erases existing Wazuh data on the affected nodes, so use it deliberately.

The `halt` command stops one machine or the whole lab while preserving its disks. The `status` command delegates to `vagrant status`. The `ssh` command opens an interactive session or runs one command on a named machine, and short names such as `indexer-1` are accepted.

```bash
vagruw halt
vagruw halt --machine wazuh-lab-indexer-2
vagruw status
vagruw ssh wazuh-lab-indexer-1
vagruw ssh wazuh-lab-indexer-1 -- hostname
```

The `destroy` command deletes every machine and its disk. Without `--force` it asks for confirmation in an interactive shell and refuses to proceed in a non-interactive shell. The `--purge` flag also deletes the private `.vagruw` directory, including the cached installer, the credentials archive, and the extracted credentials file.

```bash
vagruw destroy
vagruw destroy --force
vagruw destroy --force --purge
```

The `verify` command checks the systemd services expected on every node and, when credentials exist, queries the Wazuh indexer cluster health endpoint. The `credentials` command prints the dashboard address, the dashboard user, and the admin password. The `--show` flag prints the complete extracted credentials file.

```bash
vagruw verify
vagruw credentials
vagruw credentials --show
```

## Configuration file

The generated `vagruw.json` file is the source of truth for the lab and is intentionally human-editable. The `schema_version` field is currently `1`. The `project` field controls every machine-name prefix. The `topology` field is either `aio` or `distributed`. The `provider` field is either `virtualbox` or `libvirt`. The `box` field must name a HashiCorp generic image, such as `generic/ubuntu2204` or `generic/rocky9`. The `wazuh_version` field pins the Wazuh release and must be a supported 4.x release from 4.9 onward.

The `network` field must be a private IPv4 CIDR, and the `ip_start` field selects the first host offset. The `counts` object holds `indexers`, `servers`, and `dashboards`. The all-in-one topology requires exactly one machine, so its counts must all be one and are reset to one when the configuration is created. The distributed topology accepts up to nine indexers and up to nine servers and currently supports exactly one dashboard. The `resources` object holds a `cpus` and `memory_mb` pair for each of the `aio`, `indexer`, `server`, and `dashboard` roles. The `ignore_hardware_check` field is a boolean and controls the Wazuh assistant's `-i` flag.

Unknown top-level fields are rejected so that a misspelled setting cannot be silently ignored. Unknown roles and unknown count fields are rejected for the same reason. After editing `vagruw.json`, regenerate the Vagrantfile with the `generate` command.

```bash
vagruw generate
vagruw generate --force
```

The `generate` command refuses to replace an existing Vagrantfile unless `--force` is supplied. It does not start machines and does not install Wazuh.

## Wazuh installation flow

Vagruw downloads the official installer from the URL for the selected release series, caches it under `.vagruw/artifacts`, and verifies the `wazuh_version` and `wazuh_major` values embedded in the script. The current default is Wazuh 4.14.9 from `https://packages.wazuh.com/4.14/wazuh-install.sh`. The installer is uploaded to `/tmp/vagruw/wazuh-install.sh` on every node. The generated node configuration is written to `.vagruw/config.yml` and uploaded to the first indexer for distributed deployments.

The all-in-one flow runs the assisted installer with the all-in-one and ignore-check flags.

```bash
sudo bash /tmp/vagruw/wazuh-install.sh -a -i
```

The distributed flow first generates the certificate authority, certificates, cluster key, and passwords on the first indexer. It downloads the resulting `wazuh-install-files.tar` archive, uploads that archive to every node, installs every indexer, initializes the indexer cluster security settings, installs the Wazuh server or servers in master and worker order, and installs the dashboard. The exact commands are visible with `vagruw install --dry-run` and follow the assisted installer contract documented by Wazuh for the pinned release.

```bash
sudo bash /tmp/vagruw/wazuh-install.sh --generate-config-files
sudo bash /tmp/vagruw/wazuh-install.sh --wazuh-indexer wazuh-lab-indexer-1
sudo bash /tmp/vagruw/wazuh-install.sh --wazuh-indexer wazuh-lab-indexer-2
sudo bash /tmp/vagruw/wazuh-install.sh --wazuh-indexer wazuh-lab-indexer-3
sudo bash /tmp/vagruw/wazuh-install.sh --start-cluster
sudo bash /tmp/vagruw/wazuh-install.sh --wazuh-server wazuh-lab-server-1
sudo bash /tmp/vagruw/wazuh-install.sh --wazuh-dashboard wazuh-lab-dashboard-1
```

The automation performs the uploads and downloads around those commands, so the command examples are illustrative rather than a manual checklist. The installer receives the generated archive in its working directory, which is `/tmp/vagruw` on every node. After the archive has been fetched to the host and the installation has finished, Vagruw removes `/tmp/vagruw` from every node so the installer script and the archive containing private keys and passwords do not remain on the guests.

Wazuh 4.9 and later releases use the `server` key in `config.yml` and the `--wazuh-server` component flag for the assisted installer. Wazuh 5.x is intentionally rejected until a stable installer exists and its renamed component model has been verified. The version guard is in `src/wazuh.py`, and a new release family should be added as an explicit profile and covered by tests rather than forced through the 4.x profile.

## Credentials and verification

The assisted installer creates `wazuh-install-files.tar`, which contains the node certificates, the cluster key, and `wazuh-passwords.txt`. Vagruw fetches the archive over SSH, validates that it can be decoded as a tar archive, extracts `wazuh-passwords.txt` into `.vagruw/credentials.txt`, and sets the extracted file to mode `0600`. The `.vagruw` directory is created with mode `0700`, and the cached installer and local archive are also protected. The admin password is read from the current Wazuh password format, where an `indexer_username: 'admin'` entry is followed by its `indexer_password` entry, and the legacy quoted listing format is accepted for older projects.

The `credentials` command never reads a password from an environment variable and never sends one to the guests after installation. The password is printed only when the user explicitly asks for the command. The `.vagruw` directory is ignored by Git, and the generated project `.gitignore` also excludes the installer archive and the extracted credentials file.

The `verify` command checks `wazuh-indexer`, `wazuh-manager`, and `wazuh-dashboard` on the appropriate nodes. It then reads the local admin password and runs a local HTTPS request against the indexer cluster health endpoint. The request uses `curl -k` because the indexer uses the certificate authority generated for the lab and the health check runs against `127.0.0.1` on a lab machine. A `green` or `yellow` cluster status is treated as healthy because a single-node lab or a freshly started multi-node lab can legitimately remain yellow while replicas are allocated.

The dashboard address is derived from the dashboard node and is always HTTPS. For the default network the all-in-one dashboard is `https://192.168.56.10/` and the default distributed dashboard is `https://192.168.56.30/`. The login user is `admin` and the password is the one printed by `vagruw credentials`.

## Security notes

The generated network is host-only, the dashboard port is not forwarded to the host's public interfaces, and the Vagrant synced folder is disabled. The base bootstrap does not install a public service other than the Wazuh components, and the lab is intended for a trusted workstation. Do not expose the host-only network or the dashboard to an untrusted network without adding a firewall, TLS review, and a credential rotation plan.

The installer is fetched over HTTPS from the official Wazuh package host and its embedded version metadata is checked before use. There is no detached signature or checksum verification in the current implementation, so a compromised package host or a compromised TLS path remains a supply-chain risk. For high-assurance use, download the installer through an approved channel and pass it with `VAGRUW_INSTALLER_SOURCE`, then review the script before running the lab.

The credentials archive is sensitive because it contains the private keys and passwords for the deployment. Vagruw keeps the archive and extracted password file under `.vagruw`, sets restrictive permissions, and removes the remote copy after installation, but the host copy remains until `vagruw destroy --purge` or manual deletion. Treat `.vagruw` as a secret store and never commit it, copy it into a shared directory, or attach it to a bug report.

The default VirtualBox NAT DNS resolver setting and the private network are lab conveniences, not a production network design. The Wazuh dashboard and indexer use certificates generated for the lab and the health check deliberately bypasses certificate verification on the loopback interface. A production deployment needs a proper certificate authority, DNS, backups, monitoring, and an upgrade process. Vulnerability reporting and the supported security scope are described in `SECURITY.md`.

## Troubleshooting

If `vagruw up` fails before any guest command runs, confirm that `vagrant` is installed, that the selected provider is installed and working, and that `vagrant validate` succeeds in the project directory. The `vagruw status` command shows the current machine states. The `vagruw ssh` command can be used to inspect a guest when the automated installation stops.

If Vagrant reports a network conflict, change the `network` and possibly the `ip_start` value in `vagruw.json`, regenerate the Vagrantfile, and recreate the machines. A host-only network must not overlap a host interface, a VPN, or another lab. The default `192.168.56.0/24` network is common for VirtualBox labs and is a frequent source of conflicts.

If the Wazuh assistant reports insufficient memory or CPU, leave `ignore_hardware_check` enabled for a lab, or increase the relevant `resources` values and regenerate the Vagrantfile. The `-i` option only skips the assistant's hardware gate; it does not make an undersized guest perform well.

If the installer version does not match the pinned version, the download is rejected before anything is uploaded. Review the current official Wazuh documentation, update `wazuh_version` only after confirming the installer contract, or point `VAGRUW_INSTALLER_SOURCE` at a reviewed local script with the exact pinned version. The application intentionally refuses to silently install a different release.

If installation succeeds but credentials are missing, inspect `.vagruw/wazuh-install-files.tar` if it still exists and confirm that it contains `wazuh-install-files/wazuh-passwords.txt`. The archive is fetched before the remote cleanup step, so a missing local archive usually means the failure happened before the fetch. The installation log on a guest is `/var/log/wazuh-install.log`.

The generated Vagrantfile can be checked without starting anything with `ruby -c Vagrantfile` and `vagrant validate`. The bootstrap script can be checked with `bash -n` after extracting the heredoc or by relying on the test suite.

## Testing

The test suite contains 111 automated tests. It covers configuration validation, topology and address allocation, deterministic Vagrantfile generation, the no-indentation rule, bootstrap shell syntax, Ruby syntax, `vagrant validate` when Vagrant is installed, Wazuh version profiles, installer and command generation, credential parsing, archive extraction, upload and fetch ordering, lifecycle commands, the CLI, and a complete simulated distributed lifecycle with a fake `vagrant` executable.

```bash
python3 -m pytest
ruff check src tests
ruff format --check src tests
ruby -c Vagrantfile
ruby -c examples/distributed/Vagrantfile
vagrant validate
(cd examples/distributed && vagrant validate)
```

The simulated lifecycle test replaces only the external `vagrant` binary, the installer download, and the credentials archive. It exercises the same `init`, `up`, `install`, `credentials`, `halt`, `status`, and `destroy` code paths as a real run. A live installation that downloads packages and boots Wazuh is not part of the automated suite because it needs a real provider, network access, and several gigabytes of memory; the lab is intended to be validated with a real `vagruw up` before production-like use. The same Python tests and Vagrantfile checks run in `.github/workflows/ci.yml` on Python 3.10, 3.11, and 3.12, where the Vagrant job validates both generated examples without booting a machine.

## Project layout

The Python source modules are directly in `src`, without a nested package directory. The configuration and topology model are in `config.py` and `model.py`, the shared version constants are in `constants.py`, the Vagrantfile renderer is in `generator.py`, the Wazuh version profile and command builders are in `wazuh.py`, the lifecycle orchestration is in `orchestrator.py`, and the command-line interface is in `cli.py`. The test suite is in `tests`. The root `Vagrantfile` and `vagruw.json` are a generated all-in-one example. The `examples/distributed` directory contains the corresponding three-indexer distributed example. Contribution guidance is in `CONTRIBUTING.md`, and vulnerability reporting guidance is in `SECURITY.md`.

## Versioning and support

Vagruw is at version 0.1.0. It targets Wazuh 4.14.9 as the verified stable release and accepts other 4.x releases from 4.9 onward through the same assisted-installer profile. The profile still validates the downloaded script's embedded version, so a moving patch release cannot silently replace the pinned version. Wazuh 5.x is not supported until its stable installer and configuration contract have been verified and covered by this project's tests.

## License

Vagruw is released under the MIT License. See `LICENSE` for the full text.
