# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/) and will
use semantic versioning once the database and protocol compatibility promises
described in `docs/compatibility.md` become stable.

## Unreleased

### Added

- Release acceptance coverage spanning encrypted local operations, real TLS,
  authenticated replication, conflict resolution, verification, backup, and
  restore.
- Reproducible performance methodology and embedded-engine baselines.
- Cross-platform release-build workflow with checksums and CycloneDX SBOMs.
- Installation, quickstart, compatibility, and contribution documentation.

### Known release blockers

- Replication has no supported network transport or end-user sync command.
- Database format 5 has no migration from earlier development formats.
- CLI key files remain raw and have no OS keychain/HSM integration.
- No published compatibility fixtures or independent security review exists.

