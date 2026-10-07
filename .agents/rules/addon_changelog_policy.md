# Workspace Rule: Home Assistant Add-on Versioning & Mandatory Changelog Policy

**Scope:** `KNX IP HOME ASSISTANT GATEWAY` (`gavasah-homeassistant-addons`)

---

## Mandate

Whenever modifying, patching, or releasing any add-on (such as `gavasah-cloud-agent`):
1. **Always update `CHANGELOG.md`**:
   - Location: Inside the respective add-on folder (`gavasah-cloud-agent/CHANGELOG.md`).
   - Standard: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) with SemVer.
2. **Synchronize `config.yaml`**:
   - The `version` string in `config.yaml` must exactly match the latest released version in `CHANGELOG.md`.
3. **Sections to include**:
   - `### Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`, `### Security`.
4. **Git Commit Requirement**:
   - Git commits that bump version must reference the version and changelog updates.
