# Security policy

## Supported versions

Vagruw 0.1.x is the current supported release line. It targets Vagrant 2.4 or newer on a Linux host and supports verified Wazuh 4.x installers from 4.9 onward, with 4.14.9 as the pinned default. Wazuh 5.x is not supported, and a report that depends on an unverified major family will be treated as a feature request rather than a supported security fix.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the private security advisory feature of the repository that publishes Vagruw. If the project has not been published yet, contact the maintainer through the private channel used to obtain the code and state clearly that the report is security-sensitive.

A useful report includes the Vagruw version, the host operating system, the Vagrant version, the provider and provider version, the box name, the configuration with credentials and addresses redacted, the exact command that triggered the problem, and the relevant output. Remove passwords, private keys, `.vagruw` content, and any personal paths before sending logs. Reports about the upstream Wazuh installer, Vagrant, a provider plugin, or a box image should go to the upstream project unless Vagruw's handling of them creates the vulnerability.

## Scope

Vagruw is a lab automation tool. It creates host-only networks, runs a privileged installer on disposable virtual machines, and stores the generated credentials on the host. A report is in scope when it shows that Vagruw can be tricked into running an unintended command on the host or a guest, writing a secret to an unsafe location, exposing a secret to another local user, accepting an installer that does not match the pinned version, escaping the project directory during file operations, or deleting data outside the documented lifecycle paths.

The project does not claim to provide a production security boundary. The default network is host-only but has no host firewall. The dashboard uses certificates generated for the lab. The health check bypasses certificate verification on the loopback interface. The installer is fetched over HTTPS but is not signature-verified. The credentials archive remains on the host until it is purged. These are documented limitations rather than vulnerabilities by themselves, although a concrete exploit that makes one of them worse is still worth reporting.

## Handling expectations

The maintainer will acknowledge a private report when it is received, reproduce it on a supported configuration when possible, and coordinate a fix and disclosure. Do not publish details before a fix or mitigation has been agreed. There is no bug bounty programme. Credit can be included in the release notes when the reporter agrees.

## Hardening guidance

Run Vagruw only on a trusted workstation. Keep `.vagruw` private and delete it with `vagruw destroy --purge` when the lab is no longer needed. Do not commit the runtime directory, the credentials archive, or the extracted password listing. Review the generated Vagrantfile before the first `vagrant up`. Use an approved local installer through `VAGRUW_INSTALLER_SOURCE` when the supply chain requires review. Keep Vagrant, the provider, the box, and the Wazuh release current within the supported profile. Do not expose the host-only network or the dashboard to an untrusted network. Use a dedicated host or a dedicated network namespace when the lab must coexist with sensitive workloads.
