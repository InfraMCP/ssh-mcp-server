# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-22

### Security
- Bumped `mcp` 1.14.1 → 1.30.0, resolving four advisories (GHSA-vj7q-gjh5-988w,
  GHSA-jpw9-pfvf-9f58, GHSA-9h52-p55h-vw2f, GHSA-84m7-p3x7-pcfv).
- Bumped `paramiko` 4.0.0 → 5.1.0, resolving the SHA-1 RSA key advisory
  (GHSA-r374-rxx8-8654).
- Bumped dev tooling to clear `pip-audit` findings: `black` 24.8.0 → 26.10.1,
  `pytest` 8.3.3 → 9.1.1, `pytest-asyncio` 0.24.0 → 1.4.0, plus `isort`,
  `flake8`, and `pytest-cov`.
- Re-enabled the Safety and Dependency Security Check workflows (both had been
  auto-disabled by GitHub after repo inactivity) and added `workflow_dispatch`
  so they can be recovered manually in future.

### Changed
- Raised the minimum supported Python to 3.10 (required by both `mcp` and
  `paramiko` 5.x); dropped EOL Python 3.8/3.9 from the classifiers and tooling
  targets. This matches the Python version the README already documented.
- The CI workflow now installs the package with its dev extras and runs the
  test suite, so tests gate pull requests and future dependency bumps are
  validated by a real install + `pytest` run.
- Updated the PyPI publish workflow to build on Python 3.12 (was 3.8).

### Fixed
- Rewrote the test suite, which had drifted out of sync with the refactored
  function-based credential/server API and no longer imported (the previous
  class-based `EnvironmentProvider`/`CredentialManager` symbols and
  `execute_ssh`/`get_system_info` signatures no longer existed). 20 tests now
  pass against the current API.

## [0.1.1] - 2025-09-25

### Fixed
- Fixed version mismatch in __init__.py
- Updated README with correct Python version requirements (3.10+)
- Added status badges for automated quality checks
- Removed outdated credential management instructions

### Changed
- Improved documentation clarity and accuracy

## [0.1.0] - 2025-09-24

### Added
- Basic SSH command execution with secure credential management
- macOS Keychain credential support
- System information and administration tools
- Puppet integration for configuration management
- Comprehensive test suite and documentation
- Security workflows for dependency scanning
- Perfect pylint score (10.00/10)
