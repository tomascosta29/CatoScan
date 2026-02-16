# CatoScan v3.5.1

Patch release to fix post-3.5.0 CI issues.

## Fixes

- Fixed GitHub Actions workflow failure caused by `actions/setup-python` pip cache auto-detection when no `requirements.txt` or `pyproject.toml` exists.
- Fixed cross-platform CI test regression where RPM-specific mock assertions failed on Ubuntu runners by explicitly using the Fedora profile in that test.

## Recommendation

- Use `v3.5.1` for production.
- `v3.5.0` is superseded.
