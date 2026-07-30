# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

## [0.2.2] - Unreleased

### Added
- `rawstor-vhost`, a native vhost-user-blk backend replacing the bundled qemu libvhost-user library. Benchmarks show `rawstor-vhost` matching `rawstor-vhost-qemu` at iodepth=1 and beating it by ~3-4% IOPS with ~20-25% lower guest CPU usage at iodepth=16.

### Changed
- deb/rpm python bindings now build natively per-OS (Ubuntu 24.04/26.04, AlmaLinux 9/10).
- `debian/changelog` generated from real `ChangeLog.md`, credited per release.
- `.ddeb`/`-debuginfo` debug packages now collected consistently for both deb and rpm.

### Fixed                                                                                                                                                                                             
- Python bindings now work with `--enable-asan`.
- `rawstor-vhost` now serves front-end connections in a loop and handles a front-end disconnect cleanly, so it survives QEMU's `reconnect=1` without needing an external supervisor.
- `rawstor-vhost` no longer stops listening for virtqueue kicks after the first one, which previously stalled all I/O past the first batch of requests.
- `rawstor-vhost` now resolves virtqueue descriptor addresses (guest physical addresses) correctly instead of against the unrelated QEMU-process address range, which previously failed most real I/O with "invalid descriptor address".
- `librawio`'s multishot poll no longer redelivers a same-batch duplicate completion, which previously crashed `rawstor-vhost-qemu` at higher queue depths.

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
