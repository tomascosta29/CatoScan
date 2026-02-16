# Changelog

All notable changes to CatoScan are documented in this file.

## 3.5.1 - 2026-02-16

Patch release to correct CI pipeline regressions introduced during 3.5.0 rollout.

### Fixed
- GitHub Actions setup failure caused by `setup-python` pip caching without dependency manifests.
- Cross-platform test instability in mocked package manager assertions by pinning Fedora profile for RPM-specific tests.

### Notes
- This release supersedes 3.5.0 for production use.

## 3.5.0 - 2026-02-16

Production-ready baseline release with hardened CLI behavior, safer check execution,
and profile-driven multi-distro foundations.

### Added
- Platform profile system with profile-aware package, service, path, and remediation adapters.
- Fedora 43 baseline profile and Ubuntu 24.04 pilot profile.
- CLI profile override: `--profile <id>`.
- JSON metadata fields for platform context:
  - `schema_version`
  - `platform_profile`
  - `distribution`
  - `distribution_version`
  - `distribution_name`
  - `package_manager`
  - `service_manager`
- Discovery diagnostics via `CheckRegistry.discovery_errors`.

### Changed
- Progress bar total now reflects actual checks being executed (after filtering).
- Discovery loader now imports checks by file-path-based unique module names to avoid cache collisions.
- Core service-check family (`svc_*`) migrated from hardcoded distro commands to platform helpers.
- Key path-heavy checks migrated to profile-driven paths/commands:
  - `network_ipv6`
  - `boot_grub_permissions`
  - `boot_grub_password`
  - `selinux_bootloader`
  - `audit_grub`
  - `audit_network_changes`
- CLI/help/entrypoint naming aligned to `catoscan`.

### Fixed
- High-risk username handling in `user_last_password_change` now validates usernames before subprocess use.
- Home path safety validation for user-home and dotfile permission checks.
- Clear and consistent output write failure handling with correct exit code behavior.
- Graceful handling of broken pipe scenarios.
- Corrected CIS reference in `user_last_password_change` to 5.4.1.4.

### Compatibility
- `metadata.fedora_version` remains present for backward compatibility.
- Existing JSON consumers should continue working; new metadata fields are additive.
