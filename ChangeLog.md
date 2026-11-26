# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.7] - Unreleased

### Added

- `rawstor-mds --advertise`, `--domain` and `--weight` enter the witness the MDS hosts in its topology.
- `rawstor-ost --mds` registers the OST with the MDS of its cluster (`--id`, `--advertise`, `--domain`, `--weight`; `MDS`, `ADVERTISE`, `DOMAIN`, `WEIGHT` of `rawstor-ost@<uuid>`), every heartbeat, with a sample of its store, and as leaving when it stops.

### Changed

- `rawstor-mds` keeps its topology in its database, entered by the OSTs that register with it (`OST_REGISTER`), not in a file: `--topology`, the instance's `TOPOLOGY_PATH` and the reload on `SIGHUP` are gone; a database of an earlier build keeps its entries.
- An OST is available to the MDS for three heartbeats (`RAWSTOR_MDS_OPTS_HEARTBEAT_INTERVAL`) after it registers, instead of being probed; `RAWSTOR_MDS_OPTS_INFO_CONCURRENCY` is gone.
- The space `rawstor location info mds://` reports is sampled by the OSTs themselves, every `RAWSTOR_MDS_OPTS_INFO_INTERVAL` and `RAWSTOR_MDS_OPTS_INFO_REFRESH_DELAY` after they created or removed a member or a version.
- `rawstor-ost@<uuid>` runs with `--id=<uuid>`: with TLS, an instance whose certificate is for another id does not start.
- `rawstor-mds --reconstruct` waits for every OST of its topology to register, or for `--expect N` of them when the database is gone, answering only registrations until the map is rebuilt.

## [0.3.6] - 2026-11-26

### Added

- `RAWSTOR_OPTS_MIRROR_RESYNC_RATE` (`mirror_resync_rate` in `RawstorOpts`) limits the bytes per second the copy of a mirror resync or heal sends, over all the objects of the process; the default is no limit.
- `RAWSTOR_OPTS_EXPORT_RATE` (`export_rate` in `RawstorOpts`) limits the bytes per second the exports to a file (`rawstor object export`, `rawstor version export`, `rawstor_target_export()`) read, for each export; the default is no limit.

### Changed

- `rawstor pki issue --object-permissions` takes `UUID:rwx` (`UUID:rw-`, `UUID:---` to deny), not a numeric mask, and `rawstor pki show` prints object permissions the same way.
- `rawstor pki show`, `issue` and `renew` print the process a certificate is for (`ost`, `mds`, `admin` or `client`) as `type`, and a client's account role (`none`, `reader`, `writer` or `manager`) as `role`, not as `role` and `access_role`. pyrawstor `pki.show()` returns the account role as `role`, and `<rawstor/pki.h>` names the process `enum RawstorPkiType`, not `RawstorPkiRole`.
- `admin` and `mds` certificates no longer open objects on an OST: `SET_OBJECT`, `READ` and `LIST_VERSIONS` are refused to them, so a provider reads no account data. `rawstor object export` and `version export` need a client certificate of the object's account.

## [0.3.5] - 2026-11-25

### Changed

- `rawstor pki show` takes the certificate as an argument, `rawstor pki show FILE`, not as `--cert FILE`.
- The trust domain of a CA made by `rawstor pki init` is the URI SAN `spiffe://<trust_domain>` of its `ca.crt`, not a separate `trust_domain` file. A CA made by an earlier build is not opened: make it again.
- An I/O operation that fails with `ENOSPC` is not retried: the backend stays full until space is freed, and each retry reconnected first.

### Fixed

- `rawstor location info` kept showing the space a version had taken for up to five minutes after the version was created or removed: the MDS now probes the OSTs holding its copies, as it does after creating or resizing an object.

## [0.3.4] - 2026-11-24

### Added

- `rawstor object export` and `rawstor version export` take `--force`: a mirror below its quorum is read from the members that are reachable, as they are. `rawstor_target_export()` takes a `flags` argument for it (`RAWSTOR_FORCE`), and pyrawstor `Target.export()` a `force` one.

### Changed

- `lvm://`: a version snapshot LV is named with the whole version id, `s<uuid>-<offset>`, not the 22-character form. Snapshots created by earlier builds are no longer found.

### Fixed

- A version of an object with a witness could not be opened, so `rawstor version export` and a read-only `rawstor-vhost` on it failed with "Transport endpoint is not connected": the records of its copies list the witness among the members, which a version does not have.

## [0.3.3] - 2026-11-23

### Changed

- A request the server refuses no longer logs `Server error: ...` on its own: the error is thrown to the caller, which reports it with its context.
- `lvm://`: creating a chunk leaves 20% of the volume group free for version snapshots and fails with `ENOSPC` otherwise.
- `rawstor-ost` keeps the member records of a `file://`, `lvm://` or `zfs://` store in memory for `--meta-cache-ttl` (default 60000 ms, `0` turns it off), so polling them no longer runs `lvs` each time ([OST](docs/ost.md#member-record-cache)).

### Fixed

- `lvm://`: a version of a chunk failed with "Input/output error" because the snapshot's device-mapper name exceeded 127 characters; snapshot LVs are now named `s<version_id>-<offset>`. Snapshots created by earlier builds are no longer found.
- `lvm://`: a version whose `lvcreate` failed halfway left a snapshot LV behind that made every retry fail with "already exists"; it is now removed.
- Closing a mirrored disk logged `Server error: Bad file descriptor` and `Slot::close(): departure` for each member, and the member stayed DIRTY instead of becoming CLEAN: the durability flush of a clean departure was sent after `LEAVE`, which the server refuses; it is now sent before.

## [0.3.2] - 2026-11-22

### Fixed

- `rawstor-vhost`, `rawstor-vduse`: closing a mirrored object with a witness on an MDS logged "Function not implemented" and "Bad file descriptor" errors, and the MDS logged "Unsupported command"; a witness has no session to leave, so it is no longer sent LEAVE.
- `rawstor-ost`, `rawstor-vhost` and the other users of a receive ring: a ring with no free buffer, or a registration that the kernel ended on its own, cut the request in progress short ("Unexpected request data size"), dropped the connection and made every request in flight on it retry; the data now waits in the socket until the ring has room again.
- `rawstor-ost` and the client library: the receive ring of a connection is 32 MiB, not 128 MiB; every buffer of it ends up touched, so a server with many connections was killed by the kernel for lack of memory, and `rawstor-vhost` held that much per chunk and member.

## [0.3.1] - 2026-11-22

### Added

- `RAWSTOR_OPTS_TLS_HANDSHAKE_LIMIT` (default 1024): `rawstor-ost` and `rawstor-mds` close a new connection, unread, while that many TLS handshakes are in flight, and log the refusals ([security design](docs/security.md)).

### Changed

- Sends on one connection are no longer written one at a time: the requests that queue up while a write is in flight go out together, in one `sendmsg()` on a plain connection and in shared TLS records with one write on a TLS one. A burst of small requests is several times faster on the sender's CPU (a 512-byte request: 0.19M to 2.1M requests/s plain, 0.09M to 1.6M TLS, in a loopback microbenchmark); a lone request is about 1 µs slower.

### Fixed

- `lvm://`: creating a version failed with "LV name ... is not supported" once `<vg>/<lv>` of the snapshot passed LVM's 127-character limit (a long VG name or a large chunk offset); a snapshot's name now carries the version id in a 22-character form. Snapshots created by earlier builds are no longer found.
- Plain (`--insecure`) connections: a request that the socket sent only in part failed with EAGAIN and made the client reconnect and retry every request in flight; the rest of it is now sent.

## [0.3.0] - 2026-11-20

Upgrading from 0.2.x: the OST wire protocol, the object layout on every backend and the CLI command structure changed incompatibly; see **Changed**. Objects created by 0.2.x are not visible to this release.

### Added

- `rawstor-mds` metadata server ([design](docs/mds.md); own deb/rpm package with the `rawstor-mds@<uuid>.service` template): `mds://host:port/<id>` objects whose chunks it places across a static OST topology, usable anywhere a target is; grow-only `rawstor object resize`, `--failure-domain`/`--stripe-width` on create, topology reload on `SIGHUP`, `rawstor-mds --reconstruct` to rebuild a lost chunk map from the OSTs, `rawstor location info mds://` with cached space statistics and health probes, and `rawstor location list` for the locations of a topology.
- Multi-chunk objects: `rawstor object create --chunk-size` (`RawstorObjectSpec.chunk_size`) splits an object into equal chunks, and one target routes I/O across all of them.
- N-way mirroring ([design](docs/mirroring.md)): `rawstor object create --mirrors N` (`RawstorObjectSpec.width`, pyrawstor `width`), quorum-gated open, degrade-and-continue writes, read failover and online resync of a stale, reconnected or missing member; `rawstor object chunks`, `slots` and `resolve` inspect a mirror and recover it by hand after a split brain.
- Witness members: metadata-only chunk members that break ties for an even number of data copies; MDS places one automatically for an even width, and the topology needs a `role` column.
- Native CoW versions (`zfs://`, plus snapshot-like versions on `lvm://` and `file://`): `rawstor version create|list|show|remove`, consistent even with a live writer thanks to a write barrier across the object's chunks ([design](docs/mds.md#the-write-barrier)); a version opens only `RAWSTOR_READONLY`.
- Export and import: `rawstor object export|import|copy` and `rawstor version export` move an object or version to and from a file image or another object, with progress reporting; also in the C API (`rawstor_target_export()`, `rawstor_target_create_from_file()`, ...) and pyrawstor.
- Accounts ([design](docs/accounts.md)): an object belongs to an account named in the location (`ost://<account>@host:port`); `rawstor account create|list|remove` and `rawstor object transfer`; `list` shows each object's account.
- TLS 1.3 with mutual authentication between the client library and every service ([design](docs/security.md), [configuration](docs/configuration.md#tls)), and role- and object-level authorization from CA-signed certificates. A process without certificates refuses to start unless run with `--insecure`. `rawstor pki init|issue|renew|show` (and `rawstor_pki_*()`, `rawstor.pki`) manage a small CA. OpenSSL 3.0 or newer is a build dependency.
- An object UUID can stand in for a target: commands accept `LOCATION UUID`, or a bare `UUID` with the location taken from `RAWSTOR_LOCATION`.
- `rawstor object list --held-by LOCATION` lists the objects that have a member on one location of an MDS topology.
- `rawstor object|version|account|location` list and show commands take `--format table|json|value` and `--column`; `rawstor create|list|show|remove|info` are shorthands, and `ls`/`rm` alias `list`/`remove`.
- `--readonly` for `rawstor-vhost`, `rawstor-vhost-qemu` and `rawstor-vduse` (`--force` with it skips the mirror write quorum).
- `rawstor-vhost` supports QEMU live migration; `SIGHUP` makes `rawstor-vhost` and `rawstor-vduse` pick up a grown object and tell the guest.
- Requests in flight when `rawstor-vhost` or `rawstor-vduse` crashes are resubmitted after it restarts instead of never completing.
- `rawstor-ost@<uuid>.service` systemd template, so a host runs several OSTs; all systemd services take extra arguments through `EXTRA_ARGS`.
- Host names work wherever an IPv4 address did in `ost://`/`mds://` locations, topology files and listen addresses (IPv4 only).
- Every connection begins with `HANDSHAKE`, which negotiates optional capabilities.
- pyrawstor: `rawstor.initialize(insecure=True)`, `Target.resize()` for `mds://` objects, and bindings for all of the above (`Target.slots()`, `chunks()`, `versions()`, `meta()`, `Location.accounts()`, ...).

### Changed

- Incompatible: the OST wire protocol changed (every connection begins with `HANDSHAKE`; `LIST` entries carry a chunk offset and an account; new commands); `rawstor-ost`, `rawstor-mds` and their clients must be upgraded together.
- Incompatible: every backend stores an object per chunk (`file://` `<uuid>/<offset>/data`, LVM `<uuid>-<offset>`, ZFS `<uuid>:<offset>`), with no migration.
- Incompatible: the CLI groups its commands: `rawstor object create|list|show|remove|resize|chunks|slots|resolve`, `rawstor version ...`, `rawstor location info` replace the top-level commands; `testio` stays.
- `rawstor` prints tables by default; scripts that read a target from stdout use `--format value --column target`.
- Sizes are plain bytes without a unit suffix (`B` is still accepted), and the size unit options `-b`/`-k`/`-m`/`-g`/... go before the command (`rawstor -g location info LOCATION`).
- A URI prints without its password.
- `ost://` and `mds://` URIs and the `--bind` address of `rawstor-ost`/`rawstor-mds` default to port 7777 and 7776.
- `rawstor-vhost`, `rawstor-vhost-qemu` and `rawstor testio` default `--queue-size` to 4096; `rawstor-vduse` defaults `--num-queues` to the number of CPUs.
- The client opens exactly one connection per chunk and backend, and an open `mds://` object talks to its OSTs directly.
- `rawstor-ost` serves exactly one backend location.
- Breaking C API changes: `rawstor_target_open()` takes an `int flags` argument (`RAWSTOR_READONLY`, `RAWSTOR_FORCE`); the `rawstor_object_*2()`/`rawio_*2()` functions are gone and their callback-based shapes live under the original names; `rawstor_object_pread()`/`pwrite()`/... take `offset` as `uint64_t`; target strings from `rawstor_location_list()`/`_create()` carry the chunk offset (`<uuid>/0`).
- The README's service reference moved into `docs/`, which the source tarball and the `librawstor` deb/rpm now ship.

### Removed

- The deprecated synchronous `rawstor_object_spec()`/`_list()`/`_create()`/`_create_at()`/`_remove()`/`_open()`/`_id()`/`_location()` in favor of `rawstor_target_*()`/`rawstor_location_*()`.
- The deprecated `-l`/`--location` and `-t`/`--target` flags and the `rawstor-cli` symlink in favor of the positional `LOCATION`/`TARGET`.
- `RAWSTOR_OPTS_SESSIONS`, `rawstor --sessions` (`RawstorOpts.sessions`: breaking C API change) and the `SPEC` OST command (superseded by `META`).
- `rawstor-vhost`'s `--num-queues`: it serves as many virtqueues as QEMU sets up.
- Python `Location.__iter__`: iterate `Location.objects()` instead.

### Fixed

- `rawstor-vhost` and `rawstor-vduse` no longer freeze or crash when an OST comes back after being down for longer than the retries last.
- `rawstor-vhost` and `rawstor-vduse` let in-flight requests complete on `SIGINT`/`SIGTERM`, so a planned restart is invisible to the guest.
- A restarted `rawstor-vduse` resumes serving a device the driver is already using, and a guest that resets the device no longer hangs it.
- `rawstor-vhost` killed outright no longer leaves a socket file that blocks every restart.
- `rawstor-ost` on ZFS and LVM no longer fails with `ENOMEM` on a host with little memory.
- `rawstor-ost` answers `-ENOSYS` for an unknown command instead of dropping the connection.
- With io_uring, a connection no longer hangs when the kernel ends its multishot receive on its own.
- With the `poll()` backend, a `rawstor-ost`/`rawstor-mds` worker no longer blocks in `accept()`, which kept the server from stopping on Ctrl-C/SIGTERM.

## [0.2.12] - 2026-10-01

### Fixed
- `rawstor info` against a `file://` location reported `total` as the whole filesystem's capacity (`statvfs`'s `f_blocks * f_frsize`) rather than space accounted for by rawstor, so `available` (derived as `total - used`) could include space taken by unrelated data on the same filesystem. `total` is now `used` (rawstor's own files) plus the filesystem's actually-free space (`f_bavail * f_frsize`), matching the `lvm://`/`zfs://` backends' `total = used + available` semantics.

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

- `rawstor list` and `rawstor_location_list()` list the objects of a location.
- `rawstor-ost` deb/rpm package and `librawstor-dev` development package, built from simplified deb and rpm packaging.
- `rawstor-ost.service` systemd unit, with the user, group and data directory created at package installation.
- pyrawstor `Location` and `Target` classes replace the single `Object` class.
- Lifecycle tests for objects.

### Changed

- The default rawstor port is 7777.

### Fixed

- A server-side error is forwarded to the client as is instead of being reported as `-EPROTO`.
- Removing an object no longer leaves orphaned files behind when the removal fails.
- pyrawstor development builds get a PEP 440 compliant version.

## [0.2.0] - 2026-07-03

### Added

- Units for command line arguments.
- OST backend implementation.
- Multiqueue support, with the `rawio` public headers.
- Multishot `recv`.
- Add allocate and release methods to the OST protocol.
- Python bindings.
- Public `open`, `close`, `connect` and `accept` API, user-defined object UUIDs, and creating an object by target.
- `rawstor_fd_cancel_all()` and `rawstor_fd_recv()`/`rawstor_fd_send()` public routines.

### Changed

- The OST protocol header is public as `rawstor/protocol.h`.

### Fixed

- Multishot operations break correctly and handle `POLLHUP` in multishot `recv`.
- Cancelling an event from inside its own callback.

## [0.1.2] - 2026-07-02

### Added

- `Queue::wait_timeout()` and an option controlling the queue size.
- Asynchronous object open and close, and retry of interrupted connects.
- Version header and this changelog.

### Changed

- `librawstorstd` and `librawstorio` are renamed to `librawstd` and `librawio`.
- `RawstorObject` is redefined, and the command id moves to the head of the request frame.

### Fixed

- Graceful vhost disconnect.
- Error handling in the OST session.

## [0.1.1] - 2026-05-26

### Added

- [Location and target](docs/concepts.md) conception and the matching documentation.
- Multishot `poll`, `recv`/`send` and `accept` queue routines, and event cancellation, also by file descriptor.
- `SIGTERM` handling.
- Batch processing of completions on wait.

### Changed

- Callbacks are `std::function`s instead of task classes.

### Fixed

- Handling of `POLLERR`, `POLLHUP` and `POLLNVAL`, and `SIGPIPE` is ignored.
- Uninitialized `sockaddr` and a descriptor leak after `mkstemp`.
- A callback that throws no longer leaks its CQE data.

## [0.1.0] - 2025-12-29

### Added

- `rawstor-vhost-qemu`, a vhost-user-blk server built on the qemu libvhost-user library.
- `rawstor_fd_poll()`, `rawstor_fd_recvmsg()` and `rawstor_fd_sendmsg()` routines.

## [0.0.2] - 2026-05-26

### Added

- GoogleTest suite, `clang-format` check, tracing events with reference counts, and the `--version` command line argument.
- Warning when `TCP_NODELAY` cannot be set on a unix domain socket, and io_uring init flags.
- Release automation.

### Changed

- The previous OST backend is renamed to `ost-legacy`.
- The OST frame is split into head and body, and responses carry an explicit body.

### Fixed

- Error handling in `setup_fd` and in argument validation.
- In-flight operations fail with the right size, and cleanup on terminate.
- Handling of URI port parsing errors and the signal handler.

## [0.0.1] - 2025-12-26

### Added

- iovec routines, `rawstor_object_id()` and public header licenses.

### Changed

- The ring buffer is rewritten in C++, and the uuid routines are hidden.

### Fixed

- Timeout calculation and session lookup by file descriptor.
- The rpm release number taken from the tag.

## [0.0.0] - 2025-10-26

Initial release: the `librawstor` client with io_uring based asynchronous I/O, in-memory, file and OST object backends, the `rawstor` testio command line tool and deb/rpm packaging. Releases before 0.1.2 have no changelog of their own.
