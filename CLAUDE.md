# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Layout

This repository is the main project of a three-repo workspace; the two forks live in sibling directories:

| Directory | Description |
|-----------|-------------|
| `.` (this repo) | librawstor — async I/O library, OST server, vhost-user backend |
| `../fio/` | Fork of Jens Axboe's fio with a custom `librawstor` engine |
| `../qemu/` | Fork of QEMU with a native rawstor block driver |

---

## librawstor

### Build

```bash
./autogen.sh
./configure --prefix=${HOME}/local
make -j$(nproc)
make install
```

Key `./configure` flags:

| Flag | Effect |
|------|--------|
| `--enable-debug` | Enable DEBUG-level logging |
| `--enable-trace` | Enable TRACE-level logging |
| `--enable-asan` | Enable AddressSanitizer |
| `--without-liburing` | Fall back to poll-based I/O (no io_uring) |
| `--without-libxxhash` | Disable xxhash support |
| `--without-python3` | Skip python bindings (`pyrawstor/`) — needed on PEP 668 distros where pip refuses to install into the system python |
| `--disable-tests` | Skip building test binaries |

Required system packages: `libxxhash-dev libgtest-dev liburing-dev`

### Tests

```bash
make test          # run all tests (librawstd + librawio + integration tests)
make -C librawstd test
make -C librawio test
make -C tests test
```

CI runs tests with `--enable-asan` and sets `ASAN_OPTIONS=detect_odr_violation=0`.

If `io_uring_setup()` fails with `EPERM`, check `sysctl kernel.io_uring_disabled` — it must be `0`.

### Architecture

```
librawstd/     utilities: hash, list, mempool, URI, UUID, socket, threading, logging
librawio/      async I/O queue abstraction — io_uring (default) or poll backend
src/           librawstor.so — public C API, connection/session management
include/       public headers (rawstor.h, rawstor/{rawstor,object,rawio,protocol,version}.h)
cli/           rawstor-cli (create, remove, show, testio subcommands)
ost/           rawstor-ost — OST protocol server
vhost/         rawstor-vhost — vhost-user virtio block device backend for QEMU
pyrawstor/     python bindings
tests/         integration tests
deb/ rpm/      packaging
```

**Layer dependencies:** `src/` links against `librawio` + `librawstd`; `ost/` and `vhost/` link against `src/`.

### Storage backends (Session drivers)

The storage backend is selected by the URI scheme in `--location`. All backends implement the `rawstor::Session` abstract class (`src/session.hpp`). The factory is in `src/session.cpp`.

| Scheme | Class | Backing store | Object identity |
|--------|-------|---------------|-----------------|
| `file://` | `rawstor::file::Session` | `<path>/<uuid>.dat` + `<path>/<uuid>.spec` | files |
| `lvm://` | `rawstor::lvm::Session` | LV named `<uuid>` in a VG | block device `/dev/<vg>/<uuid>` |
| `zfs://` | `rawstor::zfs::Session` | zvol `<parent_dataset>/<uuid>` | block device `/dev/zvol/<parent_dataset>/<uuid>` |
| `ost://` | `rawstor::ost::Session` | remote OST server | forwarded via OST protocol |

`lvm::Session` and `zfs::Session` share a common base `rawstor::BlkdevSession` (`src/blkdev_session.{hpp,cpp}`) which implements `spec` (via `ioctl BLKGETSIZE64`), `set_object` (open block device), and all pread/pwrite methods. Subclasses only implement `create`/`remove` (via `lvcreate`/`lvremove` and `zfs create`/`zfs destroy` respectively). The commands are spawned with `posix_spawnp` and their exit is observed by polling a pidfd on the I/O queue; after `create`, the device node is awaited on a timerfd (bounded by the `wait_device_timeout` option). `spec` for blkdev backends reports the actual device size (LVM rounds up to the VG extent size; ZFS rounds up to volblocksize).

**URI examples:**
```
file:///var/rawstor          → objects at /var/rawstor/<uuid>.dat
lvm:///dev/rawstor_vg        → objects as LVs in VG rawstor_vg
zfs:///tank/rawstor          → objects as zvols at tank/rawstor/<uuid>
ost://127.0.0.1:9090         → remote OST server
```

LVM and ZFS backends require `lvcreate`/`lvremove`/`zfs` in PATH and appropriate privileges (root or capability delegation). The whole control plane (`create`/`remove`/`spec`/`connect`/`set_object`) and the hot I/O path (pread/pwrite) are async: blkdev commands run via `posix_spawnp` + pidfd, the file backend control plane runs in a detached worker thread (`src/worker.{hpp,cpp}`) that reports back through a pipe on the queue.

### Public API

The C public API is in `include/rawstor/rawstor.h`. Key entry points:

- `rawstor_initialize(opts)` / `rawstor_terminate()` — lib lifecycle (call once per process/worker)
- `rawstor_wait()` — drive the I/O completion loop (block until at least one event fires)
- `rawstor_fd_*` — async fd operations (read, write, send, recv, poll, accept — single-shot and multishot variants)
- `rawstor_fd_cancel(event)` / `rawstor_fd_cancel_all(fd)` — cancel in-flight operations
- `rawstor_object_open/close/pread/pwrite/spec` — object-level block I/O
- `rawstor_object_{create,remove,spec,open}_async` — non-blocking control-plane variants driven by a caller-supplied `RawIOQueue`; completion is delivered via callback

All async functions complete via callbacks (`RawstorIOCallback`). Callbacks run from an I/O completion context — avoid blocking inside them.

Every `RawstorOpts` field (`io_attempts`, `sessions`, `so_sndtimeo`, `so_rcvtimeo`, `tcp_user_timeout`, `wait_device_timeout`, `mirror_probe_interval`) can also be set via an environment variable of the same name: `RAWSTOR_OPTS_<FIELD>` (e.g. `RAWSTOR_OPTS_IO_ATTEMPTS=5`).

### Locations and Targets

- **Location** — backend address: `file:///path/to/dir` or `ost://host:port`
- **Target** — location + UUID: `ost://host:port/<uuid>` or `file:///path/<uuid>`
- Comma-separated lists activate **mirroring** (two `ost://`) or **data locality** (mixed `file://` + `ost://`)

### Code Style

C code: `std=gnu99`, C++ code: `std=c++20`. Both compile with `-Wall -Wextra -Werror`.

clang-format is LLVM-based with 4-space indent and left pointer alignment. Run formatting via `.github/tools/clang-format.sh`.

Branch naming convention: `add/<feature>`, `fix/<bug>`, `ref/<component>`.

---

## fio (librawstor engine)

### Build

fio auto-detects librawstor via `pkg-config`. Install librawstor first, then:

```bash
cd ../fio
./configure          # detects librawstor; use --disable-librawstor to skip
make -j$(nproc)
```

### Running the librawstor engine

The custom engine lives in `../fio/engines/librawstor.c`. Use `--ioengine=librawstor` and pass a rawstor target URI as `--filename`:

```bash
fio --ioengine=librawstor \
    --filename="ost://127.0.0.1:8080/<uuid>" \
    --name=randread --rw=randread --bs=4k --iodepth=32 --size=1G
```

Colons in the target URI must be escaped as `\:` in fio job files (the `.github/tools/fio.sh` helper handles this automatically).

The engine is async (`FIO_ASYNCIO_SETS_ISSUE_TIME`). It calls `rawstor_initialize(NULL)` on first file open and `rawstor_terminate()` when all files are closed. The engine sizes its `RawIOQueue` to fio's `--iodepth`.

---

## qemu (native block driver)

`../qemu` is a fork of upstream QEMU with ~20 rawstor-specific commits on top. All custom code is confined to 7 files:

```
block/rawstor.c            native rawstor block driver
block/meson.build          +1 line to wire in block/rawstor.c
meson.build                librawstor detection via cc.find_library()
meson_options.txt          --rawstor feature option (auto/enabled/disabled)
qapi/block-core.json       BlockdevOptionsRawstor, BlockdevCreateOptionsRawstor
scripts/meson-buildoptions.sh  --enable/disable-rawstor passthrough
README.md                  build instructions
```

### Build

Requires librawstor installed first. Out-of-tree build:

```bash
export PKG_CONFIG_PATH=${HOME}/local/lib/pkgconfig
mkdir ../qemu/build && cd ../qemu/build
../configure \
    --extra-cflags="$(pkg-config --cflags rawstor)" \
    --extra-ldflags="$(pkg-config --libs rawstor)"
make -j$(nproc)
```

The rawstor feature is auto-detected; force it with `-Drawstor=enabled` (meson) or `--enable-rawstor` (configure wrapper).

### Block driver design

`block/rawstor.c` registers the `rawstor` protocol driver. Key design points:

- **Thread model:** A dedicated `rawstor_thread` runs the librawstor event loop (`rawstor_wait()`) in a separate thread. QEMU coroutines communicate with it by writing a `RawstorTask*` pointer over a `pipe()`. The rawstor completion callback schedules a bottom-half (`aio_bh_schedule_oneshot`) back on the QEMU AIO context to wake the coroutine.
- **URI syntax:** Block devices are addressed as `rawstor:object-uri=<target>` — the driver's `parse_filename` splits this key=value string. Colons inside a URI value must be escaped with `\`.
- **Max transfer:** Hard-capped at 4096 bytes (`bdrv_refresh_limits`). This is a known limitation (no comment in code).
- **QAPI types:** `BlockdevOptionsRawstor { object-uri: str }` and `BlockdevCreateOptionsRawstor { size, *uri }`.

### Example QEMU invocation

```bash
qemu-system-x86_64 \
    -blockdev rawstor,node-name=stor,object-uri=ost://127.0.0.1:8080/<uuid> \
    -device virtio-blk-pci,drive=stor
```
