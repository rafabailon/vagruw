# Contributing to Vagruw

## Before you start

Vagruw is a Python 3.10 or newer project with no runtime dependencies outside the standard library. Development and validation use pytest, ruff, Ruby, and Vagrant. A working VirtualBox or libvirt provider is needed only for a real lab run, not for the automated suite. Open an issue before a large behavioural change so the topology, version policy, and secret-handling trade-offs can be agreed before code is written.

## Development setup

Create a virtual environment, install the project in editable mode with the development extras, and confirm that the command-line entry point works.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e ".[dev]"
vagruw --help
```

The test suite uses the flat `src` layout through the pytest configuration, so no additional `PYTHONPATH` is needed after installation. Running the tests without installing is also supported with an explicit path.

```bash
PYTHONPATH=src python3 -m pytest
ruff check src tests
ruff format --check src tests
```

## What to test

Every behavioural change needs a test. Pure configuration and generation changes belong in `tests/test_config.py` or `tests/test_generator.py`. Installer profile and command changes belong in `tests/test_wazuh.py`. Plan ordering, execution, credential handling, and lifecycle changes belong in `tests/test_orchestrator.py`. CLI parsing and prompt changes belong in `tests/test_cli.py`. A change that affects the composed flow should extend `tests/test_end_to_end.py`, which replaces only the external `vagrant` binary, the installer source, and the credentials archive.

Do not add a test that downloads Wazuh, boots a virtual machine, or requires a provider. The default suite must remain fast, deterministic, and usable on a host without virtualization. If a change cannot be verified without a live lab, describe the manual validation in the pull request and keep the automated coverage focused on the deterministic part.

## Code style

The Python code targets 3.10 and uses type hints, dataclasses, and small functions. Run ruff before submitting. The project does not use a formatter other than `ruff format`, so do not hand-align code or introduce a second style.

Generated Vagrantfiles and bootstrap scripts keep every Ruby and Bash statement at column zero. This is a deliberate project rule. The generator tests reject indentation in generated output, and new generator code must preserve that property. Documentation prose is also written at column zero without decorative indentation, and bullet lists are avoided in favour of complete sentences. Code blocks are not indented.

## Changing configuration or topology

A new configuration field needs validation, serialisation, a default, documentation in README.md, and tests for the valid and invalid cases. A new topology or count rule needs address allocation, node naming, role handling, generated `config.yml`, installation ordering, verification, and end-to-end coverage. Keep the generated schema version stable unless the change is intentionally breaking, and reject unknown fields rather than silently ignoring them.

## Changing the Wazuh version

Do not change the default Wazuh version because a newer release exists. First read the official installation documentation for the target release, verify the assisted installer flags and configuration keys, confirm the embedded `wazuh_major` and `wazuh_version` declarations in the downloaded script, and run a real all-in-one or distributed installation. Then update the profile or add a new one, add tests for the new contract, update the default only when the release is stable, regenerate the root and example Vagrantfiles, and record the evidence in README.md.

Wazuh 5.x must not be forced through the 4.x profile. A new major family needs an explicit profile, a reviewed command contract, and tests that prove the generated configuration and installation order.

## Regenerating examples

The root `Vagrantfile` and `vagruw.json` are a generated all-in-one example. The `examples/distributed` directory is a generated three-indexer example. When generator or configuration defaults change, regenerate both and validate them.

```bash
vagruw generate --force
(cd examples/distributed && vagruw generate --force)
ruby -c Vagrantfile
(cd examples/distributed && ruby -c Vagrantfile)
vagrant validate
(cd examples/distributed && vagrant validate)
```

Review the diff before committing. A generated change that is unrelated to the intended work usually means the generator or a default changed accidentally.

## Secrets and generated files

Never commit `.vagrant`, `.vagruw`, `credentials.txt`, `wazuh-install-files.tar`, `wazuh-passwords.txt`, or a generated `config.yml` outside the project sources. The repository `.gitignore` covers the runtime paths, but a manual check is still required before a pull request. Do not paste a real password, private key, certificate archive, or unredacted installation log into an issue, a pull request, a test, or a screenshot. Use the synthetic credentials fixture when a test needs password data.

## Pull requests

A pull request should explain the problem, the chosen approach, the user-visible effect, the tests that were run, and any manual validation that was performed. Keep unrelated refactoring out of the same change. Update README.md or SECURITY.md when the change affects a documented claim, a verified version, or a security property. Confirm that the CI workflow passes and that no generated or secret file is included.

## Commit messages

Use a short imperative subject and a body that explains why the change is needed. Mention the affected command or module when it helps a reviewer. Do not claim a live Wazuh validation that was not performed, and do not describe a test as an integration test when it uses a simulated provider.

## License

By contributing, you agree that your contribution is released under the MIT License in LICENSE. Do not contribute code that you cannot license on those terms.
