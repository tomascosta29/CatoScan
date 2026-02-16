# CatoScan v3.5.0

Production-ready baseline release with hardened CLI behavior, safer check execution,
and profile-driven multi-distro foundations.

## Highlights

- Platform profile system for package/service/path/remediation abstraction
- Fedora 43 baseline profile and Ubuntu 24.04 pilot profile
- CLI profile override: `--profile <id>`
- JSON metadata contract additions:
  - `schema_version`
  - `platform_profile`
  - `distribution`
  - `distribution_version`
  - `distribution_name`
  - `package_manager`
  - `service_manager`
- Discovery diagnostics via `CheckRegistry.discovery_errors`

## Reliability and Hardening

- Output write failures now produce explicit errors with correct exit codes
- Graceful broken-pipe handling for piped command usage
- Progress totals now match filtered executed checks
- Discovery loader hardened against import-cache/module-name collisions
- Safer handling of usernames and home paths in user/account checks

## Compatibility Notes

- `metadata.fedora_version` remains in output for backward compatibility
- New metadata fields are additive and safe for existing consumers

## Validation

- Full test suite passing: `169 passed`
