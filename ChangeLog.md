# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - Unreleased

### Changed
- deb/rpm python bindings now build natively per-OS (Ubuntu 24.04/26.04, AlmaLinux 9/10).
- `debian/changelog` generated from real `ChangeLog.md`, credited per release.
- `.ddeb`/`-debuginfo` debug packages now collected consistently for both deb and rpm.

### Fixed                                                                                                                                                                                             
- Python bindings now work with `--enable-asan`.

### Removed
- Ubuntu 22.04 dropped (liburing too old); now requires `liburing >= 2.3` explicitly.

## [0.2.1] - 2026-06-14

### Added

- List objects.
- rawstor-ost and librawstor-dev packages.
- systemd service for rawstor-ost.

## [0.2.0] - 2026-06-03

### Added

- Multishot IO operations.
- Units for command line arguments.
- [Location and target](docs/locations_and_targets.md) conception.
- OST backend implementation.
- Multiqueue support.
- Add allocate and release methods to the OST protocol.
- Python bindings.

## [0.1.2] - 2026-06-02

## [0.1.1] - 2026-05-26

## [0.1.0] - 2025-12-29

## [0.0.2] - 2026-05-26

## [0.0.1] - 2025-12-29

## [0.0.0] - 2025-10-26
