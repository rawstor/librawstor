# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added
- Native CoW snapshots (`zfs://` only; `-ENOTSUP` elsewhere): `rawstor snapshot TARGET [-u UUID]` (`rawstor_target_create_snapshot()`, `pyrawstor`'s `Target.create_snapshot()`) creates one, picking the version id one of three ways -- verbatim from an already-bound `TARGET`, a caller-chosen id via `-u`/`uuid=`, or a freshly generated one otherwise (combining an already-bound `TARGET` with `-u`/`uuid=` is rejected with `-EINVAL`) -- and returns the resulting `TARGET/SNAPSHOT_ID` target string (not just the bare id), ready to pass straight to `rawstor remove`/`rawstor_target_remove()` (a target string that carries a bound snapshot version) to remove it. `rawstor create`/`rawstor_target_create()` is now only ever for a fresh object -- passing it a `TARGET` that already carries a bound snapshot version fails with `-EINVAL` instead of taking a snapshot; `rawstor snapshot`/`rawstor_target_create_snapshot()` above is the only way to do that. Plus the new `rawstor_target_snapshot_id()` (`<rawstor/target.h>`).
- `--write-cache=on|off` for `rawstor-vhost` and `rawstor-vhost-qemu` (default `off`, write-through): advertises `VIRTIO_BLK_F_CONFIG_WCE` and honors the guest live-toggling it via `SET_CONFIG`. With write-cache off, every write is made durable (`sync=true`) since the guest treats a completed write as already durable and won't issue a `FLUSH`.
- [Mirroring design](docs/mirroring.md): failure model, quorum rules and online resync for N-way mirrors.
- Per-copy object metadata (state/epoch/sync_id/history) via new `META`/`SET_SYNC_STATE`/`FLUSH` OST protocol commands and the public `rawstor_target_spec()`/`rawstor_target_meta()`/`rawstor_target_set_sync_state()` (`<rawstor/target.h>`) API. Setting mirror consistency state by hand is a sharp tool, not meant for routine application use.
- Every backend now persists per-copy metadata durably: a companion `.meta` file for `file://`, native transactional storage for `lvm://` (an LVM tag) and `zfs://` (a ZFS user property).
- `rawstor_target_create()`/`rawstor_location_create()` reject `-EINVAL` for width `0`, or for a target/location string naming more than one URI whose width doesn't match that count exactly; a lone URI accepts any nonzero width instead, as the caller's own chosen redundancy for that one copy.
- Mirrored objects now tolerate member loss: quorum-gated open (`-ENOTCONN`/`-ENOTRECOVERABLE` otherwise), degrade-and-continue writes, read failover, and automatic online resync of a stale or reconnected member while the object stays live.
- `-m`/`--mirrors N` (required) for `rawstor create`, and the matching `width` field on `pyrawstor`'s `ObjectSpec`/`Target.create()`/`Location.create()` (also required, no default); `-v`/`--verbose` for `rawstor show` (one `chunk[OFFSET]` block per chunk, each with a `mirror[N]` per copy of that chunk, position in the chunk's own comma-separated order) and pyrawstor's new `Target.meta(offset=0)` (returning one `ObjectMeta`, or `None` for a mirror that didn't answer, per mirror of the chunk at `offset`) print every copy's own consistency state (not just one).
- `rawstor resolve TARGET --winner=N[,N...] [--offset OFFSET]` for manual split-brain recovery (docs/mirroring.md, case F9): declares one or more mirrors of the chunk at `--offset` (same index `rawstor show -v` labels; every chunk in the object if `--offset` is omitted) jointly authoritative, and every mirror of that chunk not listed gets a full online resync on the next open.
- `RawstorObjectSpec` gains `chunk_size`: a target string naming more than one chunk's own uris is now a real, usable multi-chunk object -- `rawstor_target_create()` splits its own size across every chunk, and `rawstor_target_open()` returns a single object whose reads/writes are routed across all of them. Building such a target string by hand is still the only way to reach this (nothing yet allocates or advertises chunk placement); a URI's own trailing offset segment is hexadecimal, matching every other numeric field a chunk's own persisted metadata carries.

### Changed
- The packaged `rawstor-vhost@.service` systemd unit now defaults `RAWSTOR_WRITE_CACHE` to `on` instead of `off`: forcing a journal commit on every write (write-cache off) was measured to stall write round-trip times into the tens of seconds under concurrent load on a host whose backing filesystem commits slowly, while any modern guest kernel already issues an explicit flush when it needs durability.
- `rawstor_object_pwrite()`/`rawstor_object_pwritev()` gained a `sync` parameter — when true, the write is durable on stable storage by the time the callback reports success. Breaking C API change; existing callers need to pass a `sync` argument (`false` preserves the old behavior).
- `rawstor_object_spec()`/`_list()`/`_create()`/`_create_at()`/`_remove()`/`_open()`/`_id()`/`_location()` dropped in favor of the async `rawstor_target_spec()`/`_create()`/`_remove()`/`_open()`/`_id()`/`_location()` (`<rawstor/target.h>`) and `rawstor_location_list()`/`_create()` (`<rawstor/location.h>`) API, and `rawstor_object_close()` is now async too (queues and returns immediately, reporting completion via a new callback parameter that no longer carries the redundant `RawstorObject* object`). Breaking C API change; `<rawstor.h>` still pulls in every header.
- `rawio_fsync()`/`_open()`/`_close()`/`_poll()`/`_poll_multishot()`/`_connect()`/`_accept()`/`_accept_multishot()`'s completion callback collapsed to a single `ssize_t result` (0 or negative errno), matching the read/write family's own shape. Breaking C API change.
- `RawstorObjectSyncStateValue` gained an explicit `RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE = 0`; `CLEAN`/`DIRTY`/`SYNCING` now start at 1, so a zero-filled `RawstorObjectMeta` is never mistaken for a real CLEAN copy. Breaking C API change.
- `rawstor_target_meta()`/`rawstor_target_set_sync_state()` gain a mandatory `offset` parameter and now each touch exactly one chunk (the one at `offset`, `-ENOENT` if the target has none there) instead of the whole target -- a caller wanting every chunk loops over each one's own offset itself (`rawstor_target_spec()`'s own size/chunk_size say how many there are). `rawstor_target_meta()` also fills one `RawstorObjectMeta` per URI of that chunk instead of just the first reachable copy's record (a URI that doesn't answer gets a `RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE` entry); `count` is now a buffer capacity, and `result` is that chunk's own URI count (same truncation convention as `rawstor_target_id()`/`_location()`). Breaking C API change.

### Removed
- Dropped the deprecated `-l`/`--location` and `-t`/`--target` flags (`rawstor list`/`create`/`remove`/`show`/`testio`, `rawstor-ost`, `rawstor-vhost`) in favor of the positional `LOCATION`/`TARGET` argument; `rawstor create -t TARGET` (create-by-target) is unaffected. Also dropped the `rawstor-cli` compat symlink from the deb/rpm packages — use `rawstor`.
- Dropped the automatic migration of pre-0.2.4 `file://` objects (`<uuid>.dat`/`<uuid>.spec` pairs) to the current single-file format; such objects are no longer readable.
- Retired the `SPEC` OST wire command (`RAWSTOR_CMD_SPEC`, added in 0.2.3): `rawstor_target_spec()` is now `rawstor_target_meta()` under the hood (no backend ever answered `SPEC` with more than a subset of a real per-copy identity anyway). A `rawstor-ost` from this release rejects `SPEC` with `-ENOSYS`; an older client speaking to it needs to be upgraded.

### Fixed
- `rawstor-ost` now answers `-ENOSYS` for a command it doesn't recognize instead of just dropping the connection, so a newer client can tell "unsupported" apart from a transport failure.

## [0.2.12] - Unreleased

### Fixed
- `rawstor info` against a `file://` location reported `total` as the whole filesystem's capacity (`statvfs`'s `f_blocks * f_frsize`) rather than space accounted for by rawstor, so `available` (derived as `total - used`) could include space taken by unrelated data on the same filesystem. `total` is now `used` (rawstor's own files) plus the filesystem's actually-free space (`f_bavail * f_frsize`), matching the `lvm://`/`zfs://` backends' `total = used + available` semantics.
- The `rawstor-vduse` deb/rpm packages (present since 0.2.10) were never actually built or published: CI's packaging jobs never copied its install scriptlets into place, so its `.deb`/`.rpm` were silently absent from every release despite `rawstor-vduse` being a real, working binary.

## [0.2.11] - 2026-09-15

### Added
- Vendored [nlohmann/json](https://github.com/nlohmann/json) (single-header, MIT) for parsing command output in the new storage backends below.
- New `lvm://` storage backend: objects are LVM Logical Volumes, provisioned via `lvcreate`/`lvremove`. A new object is fully zeroed before it becomes visible (LVM itself only zeroes the first 4KiB of a new LV), so it never exposes another object's leftover data; any staging LV left behind by a process that crashed mid-create is swept and removed on the next `create()` against that VG.
- New `zfs://` storage backend: objects are ZFS zvols, provisioned via `zfs create`/`zfs destroy`.
- Consistent startup/connection INFO logging across `rawstor-ost`, `rawstor-vhost`, `rawstor-vhost-qemu` and `rawstor-vduse`: version at startup, waiting for a connection, client connected, client disconnected.
- `rawio::Queue::timeout_multishot()` (and its `rawio_timeout_multishot()` C API counterpart): the multishot counterpart of `timeout()`, firing once every given number of microseconds until canceled instead of resolving once.

### Changed
- The packaged `rawstor-ost.service` systemd unit's backing store is now configurable via a `LOCATION` environment variable (default `file:///var/lib/rawstor`, unchanged) instead of being hardcoded in `ExecStart` — set it in `/etc/rawstor-ost.conf`, same as the unit's other overridable settings.

### Fixed
- `rawstor create`/`list`/`remove`/`show`/`info` against a multi-backend `LOCATION`/`TARGET` (comma-separated URIs) could intermittently fail with "No buffer space available": the CLI's internal I/O queue was sized for a single backend at a time.
- The same "No buffer space available" (`ENOBUFS`) failure could also surface under a small enough `--queue-size` (io_uring builds only): the submission ring is now flushed and retried instead of failing outright when it's full of not-yet-submitted entries.
- `Object::flush()` could report success (and durability) before a write it was still waiting on had actually completed, if a later write happened to finish first -- affects `ost://`, where responses are matched by request id and can legitimately arrive out of order.
- Building with GCC 15.2.0 could hit an internal compiler error in `Connection::_with_retry()`'s coroutine code.

## [0.2.10] - 2026-08-31

### Added
- `rawio::Queue::timeout()` (and its `rawio_timeout()` C API counterpart): a standalone async timer op, co_await-able and cancellable exactly like every other `rawio::Queue` operation, resolving successfully once a given number of microseconds have elapsed.
- `-w`/`--workers N` for `rawstor-ost`: runs `N` worker threads (default `12`), each with its own I/O queue and client connections, all accepting on the same listening socket.
- `--num-queues N` for `rawstor-vhost` (default `4`): advertises `N` virtqueues over `VIRTIO_BLK_F_MQ`, each serviced by its own thread and its own connection to `TARGET`, so I/O on different queues now makes progress in parallel instead of funneling through one shared reactor.
- Discard and write-zeroes support end to end: new `rawstor_object_discard()`/`rawstor_object_write_zeroes()` client API, a `WRITE_ZEROES` OST wire command (`DISCARD` already existed but was unimplemented), `file://`'s backend now actually punches holes/zeroes ranges via `fallocate()`, and `rawstor-vhost`/`rawstor-vhost-qemu` advertise `VIRTIO_BLK_F_DISCARD`/`VIRTIO_BLK_F_WRITE_ZEROES` to the guest.
- `rawstor-vduse`: a new virtio-blk backend using the [VDUSE](https://docs.kernel.org/userspace-api/vduse.html) (vDPA Device in Userspace) kernel protocol, alongside `rawstor-vhost`. Implements the protocol natively (no vendored third-party library, same approach as `vhost/`), in its own deb/rpm package with a `rawstor-vduse@.service` systemd template unit and udev rule. Advertises `VIRTIO_BLK_F_MQ`/`VIRTIO_BLK_F_DISCARD`/`VIRTIO_BLK_F_WRITE_ZEROES` and services `_DISCARD`/`_WRITE_ZEROES` requests, and (`--num-queues`, default `16`) services that many virtqueues in parallel, each on its own thread and its own connection to `TARGET`. Linux-only. See the top-level README's "rawstor-vduse" section.
- `Connection::_with_retry()` now waits out an exponential backoff with jitter (tunable via the new `RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE`/`_MAX`/`_JITTER`) instead of retrying immediately, and reconnects before every retry regardless of what failed, bounded by `RAWSTOR_OPTS_IO_ATTEMPTS` -- skipped entirely for a rejection retrying can never fix, e.g. `ENOENT`. See README.md's "Environment Variables" section.

### Fixed
- `file://`'s `Session::create()` only `ftruncate()`d a new object to its full size, leaving it sparse; a write into never-touched territory then depends on the filesystem's own delayed allocation, which under `data=ordered` journaling must land before the next journal commit -- on an ext4 mount with an unusually long `commit=` interval, many concurrent writes into a still-sparse object could each back up behind that interval, measured as tens of seconds of `rawstor-vhost`/OST session round-trip latency under sustained load. `create()` now preallocates the object's real blocks up front (`fallocate()` on Linux, `fcntl(F_PREALLOCATE)` on macOS), removing that dependency entirely.
- `rawstor-ost` now reliably stops on the first `SIGINT`/`SIGTERM` instead of occasionally needing a second signal to unblock its I/O wait.

## [0.2.9] - 2026-08-26

### Added
- `librawstor`'s top-10 slowest-requests report now shows each entry's own submission/round-trip/callback latency breakdown, not just its total.
- `rawio_fsync()`/`_open()`/`_close()`/`_poll()`/`_poll_multishot()`/`_connect()`/`_accept()`/`_accept_multishot()` gained `_2`-suffixed siblings with a single collapsed `ssize_t` result callback, ahead of the breaking rename in 0.3.0.
- New async `rawstor_target_spec()`/`_create()`/`_remove()`/`_open()`/`_id()`/`_location()` and `rawstor_location_list()`/`_create()` API (`<rawstor/target.h>`, `<rawstor/location.h>`), plus async completion for `rawstor_object_close()`; the existing synchronous `rawstor_object_*()` API keeps working unchanged.
- `rawstor info` gained `-l`/`--logical`, additionally reporting the sum of every object's own declared size alongside the location's actual physical usage.

### Changed
- `librawio` and `librawstor`'s client-side (`Session`/`Connection`/`Object`) internals moved from callback-based async I/O to C++20 coroutines; no public API change.
- Write-throttling (in-flight cap + backlog cap on writes headed to a `file://` backing store) moved from `rawstor-ost` itself into `librawstor`'s own `file://` write path, so it now applies to any writer against a `file://` location, not just `rawstor-ost`. `rawstor-ost --write-throttle-limit`/`--write-backlog-capacity` are gone; tune the same caps via the `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT`/`RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY` environment variables instead (same defaults, 128 and 256MiB) — `rawstor-ost.service` no longer warns on startup if the limit sits too close to `--queue-size`.

### Fixed
- `rawstor_object_flush()` could report success while a `pwrite()`/`pwritev()` issued just before it was still outstanding, so its data wasn't actually guaranteed durable yet; `flush()` now waits for every write issued before it to complete first.
- `rawstor_object_close()` didn't actually flush pending writes before completing, despite already being documented to -- it now does, and also waits for any write still in flight rather than racing its connection out from under it.
- `rawstor-ost` and the client's own OST session each registered a 32MiB `recv_multishot` buffer pool, undersized for `rawstor-vhost`'s own healthy worst case (its default write-throttle-limit of 128 concurrent requests at a realistic virtio-blk transfer size); a client pipelining that many requests could overflow it, forcing a reconnect that immediately overflowed again under the same sustained load and exhausted the retry budget for real. Raised to 128MiB on both sides.
- Telemetry's in-flight-requests count could go negative: an op whose session had already died before it was ever registered still ran through the same completion path as a normal one, decrementing a count it had never gotten to increment.

## [0.2.8] - 2026-08-15

### Changed
- `rawstor-ost --queue-size`'s default raised from 256 to 4096, now that per-session write concurrency is bounded (see Fixed below) and no longer needs a small ring to keep worst-case exposure in check.
- `rawstor-ost.service` exposes `--queue-size`/`--write-throttle-limit`/`--write-backlog-capacity` as the `QUEUE_SIZE`/`WRITE_THROTTLE_LIMIT`/`WRITE_BACKLOG_CAPACITY` environment variables, overridable in `/etc/rawstor-ost.conf` like the rest of its tuning knobs.

### Fixed
- `rawstor-ost` had no limit on how many WRITEs a session could have dispatched to storage at once; against a backing store much slower than the incoming write rate, that queue grew without bound instead of applying ordinary backpressure, eventually stalling the session (and, under sustained pressure, the whole process) for an effectively unbounded time. Now capped per session via the new `--write-throttle-limit` (default 128); `rawstor-ost` also now warns on startup if it's set too close to `--queue-size` to leave any real headroom.
- Even with `--write-throttle-limit` in place, a session facing a backing store slower than its incoming write rate could still queue an unbounded number of already-received writes waiting for a dispatch slot, growing memory use without bound. Now capped in bytes via the new `--write-backlog-capacity` (default 256MiB); a write that would push the backlog over the cap is rejected with `EBUSY` instead of queued.

## [0.2.7] - 2026-08-13

### Added
- `librawstor` tracks I/O latency breakdown (submission/round-trip/callback/total), retry counts, concurrent in-flight requests, and the 10 slowest requests, reporting them to stderr from `rawstor_terminate()`. Collected by default; pass `--disable-telemetry` to `configure` to opt out (no-op and zero-cost when disabled).
- Publish the Python bindings as a single `abi3` wheel (Python >= 3.9), dynamically linked against a separately-installed `librawstor`, alongside the existing `python3-rawstor` deb/rpm packages.
- `rawstor create`/`list`/`info` fall back to the `RAWSTOR_LOCATION` environment variable when `LOCATION` is omitted from the command line.
- `rawstor info` rounds `used`/`available`/`total` to a human-readable unit by default (e.g. `~140G` instead of `147357440K`), prefixing rounded values with `~`; `-b`/`-k`/`-m`/`-g`/`-t`/`-p`/`-e` force a specific unit instead.

## [0.2.6] - 2026-08-10

### Changed
- `rawstor-ost.service`/`rawstor-vhost@.service` now document and pass through all `RAWSTOR_OPTS_*` client/server tuning environment variables (previously only `BIND_ADDR`/`RAWSTOR_LOCATION`/`RAWSTOR_WRITE_CACHE`).

### Fixed
- An OST client/server request whose own send hadn't finished yet when its connection failed and reconnected could be permanently stranded — never receiving a response or an error — hanging its caller indefinitely instead of failing or retrying.

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
