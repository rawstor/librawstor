# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - Unreleased

### Changed
- `rawstor-ost.service`/`rawstor-vhost@.service` now document and pass through all `RAWSTOR_OPTS_*` client/server tuning environment variables (previously only `BIND_ADDR`/`RAWSTOR_LOCATION`/`RAWSTOR_WRITE_CACHE`).

## [0.2.5] - 2026-08-07

### Added
- `rawstor_object_flush()`: a durability barrier — once its callback reports success, every write that completed before the call is guaranteed durable. Backed by `fdatasync()` (`F_FULLFSYNC` on macOS) for `file://`, and a new `RAWSTOR_CMD_FLUSH` OST wire command for `ost://`.
- `rawstor-vhost` and `rawstor-vhost-qemu` now implement `VIRTIO_BLK_T_FLUSH` (via `rawstor_object_flush()`) instead of responding `VIRTIO_BLK_S_UNSUPP`, and advertise the `VIRTIO_BLK_F_FLUSH` feature.

### Changed
- `librawstor` no longer ignores `SIGPIPE` process-wide; OST client/server writes and the `rawstor-vhost` control-socket write now suppress it per-call via `MSG_NOSIGNAL` (`SO_NOSIGPIPE` on macOS) instead. `rawstor-vhost-qemu` still ignores `SIGPIPE` process-wide, since the vendored `libvhost-user` writes to its control socket without `MSG_NOSIGNAL` and can't be patched.

### Fixed
- A short write on an OST connection (client or server) now triggers a reconnect instead of leaving the connection open with a desynchronized byte stream.

## [0.2.4] - 2026-08-06

### Added
- `rawstor info LOCATION` (`librawstor`'s `rawstor_location_info()`, `pyrawstor`'s `Location.info()`) reports used/total bytes for a location; for a comma-separated location, `total` is the minimum across backends and `used` is the maximum.

### Changed
- `rawstor-vhost` now ships as its own deb/rpm package instead of being bundled in `librawstor`; shares `rawstor-ost`'s `rawstor` user/group, no `libvirt` dependency.
- `rawstor`, `rawstor-ost` and `rawstor-vhost` now exit with `sysexits.h` codes (`EX_USAGE`, `EX_NOINPUT`, `EX_UNAVAILABLE`, `EX_NOPERM`, ...) instead of a generic `1` for every failure; `rawstor-ost.service`/`rawstor-vhost@.service` won't restart-loop on `EX_NOINPUT`/`EX_NOPERM`.
- `file://` backend objects are now stored as a single bare file per object instead of a `<uuid>.dat`/`<uuid>.spec` pair; a pre-existing `.dat`/`.spec` pair is transparently migrated to the new format (and the old files removed) the next time the object is accessed.

### Fixed
- `rawstor-vhost` now `chmod()` its vhost-user socket to `0660` after `bind()`, instead of leaving it at the umask default (`0755`), which silently blocked group-based QEMU access.

## [0.2.3] - 2026-08-04

### Added
- `rawstor-vhost@.service`, a systemd template unit (packaged in `librawstor`) so callers can `systemctl enable --now rawstor-vhost@<uuid>` instead of supervising `rawstor-vhost` themselves. Derives its target from the instance name alone: `${RAWSTOR_LOCATION}/<uuid>`.
- `rawstor-ost` now serves `SPEC` over the wire (new `RAWSTOR_CMD_SPEC` command); `librawstor`'s `ost://` client implements `rawstor_object_spec()` for real instead of returning an emulated fixed size.

## [0.2.2] - 2026-08-03

### Added
- `rawstor-vhost`, a native vhost-user-blk backend replacing the bundled qemu libvhost-user library. Benchmarks show `rawstor-vhost` matching `rawstor-vhost-qemu` at iodepth=1 and beating it by ~3-4% IOPS with ~20-25% lower guest CPU usage at iodepth=16.

### Changed
- deb/rpm python bindings now build natively per-OS (Ubuntu 24.04/26.04, AlmaLinux 9/10).
- `debian/changelog` generated from real `ChangeLog.md`, credited per release.
- `.ddeb`/`-debuginfo` debug packages now collected consistently for both deb and rpm.

### Fixed                                                                                                                                                                                             
- Python bindings now work with `--enable-asan`.
- `librawio`'s multishot poll no longer redelivers a same-batch duplicate completion, which previously crashed `rawstor-vhost-qemu` at higher queue depths.

### Removed
- Ubuntu 22.04 dropped (liburing too old); now requires `liburing >= 2.3` explicitly.

## [0.2.1] - 2026-07-14

### Added

- List objects.
- rawstor-ost and librawstor-dev packages.
- systemd service for rawstor-ost.

## [0.2.0] - 2026-07-03

### Added

- Multishot IO operations.
- Units for command line arguments.
- [Location and target](docs/locations_and_targets.md) conception.
- OST backend implementation.
- Multiqueue support.
- Add allocate and release methods to the OST protocol.
- Python bindings.

## [0.1.2] - 2026-07-02

## [0.1.1] - 2026-05-26

## [0.1.0] - 2025-12-29

## [0.0.2] - 2026-05-26

## [0.0.1] - 2025-12-29

## [0.0.0] - 2025-10-26
