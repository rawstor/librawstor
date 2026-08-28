# librawstor Agent Guide

## What this project is

Rawstor is a raw object storage system: a client library plus a small
family of servers/backends that let a network-addressable "object"
(identified by a UUID v7) be read and written like a raw block device.
The two headline consumers are:

- `rawstor` (the CLI, `cli/`) / `librawstor` client API —
  create/open/read/write/list objects directly.
- `rawstor-vhost` / `rawstor-vhost-qemu` — expose a rawstor object to a
  QEMU guest as a `virtio-blk` disk via the vhost-user protocol, so a VM's
  virtual disk is really just a rawstor object over the network.
- `rawstor-vduse` — same idea, over the Linux kernel's VDUSE (vDPA Device
  in Userspace) protocol instead of vhost-user: creates a real kernel vDPA
  device any `virtio-vdpa`/`vhost-vdpa` consumer can use, not just QEMU.

## Core concepts

- **Location**: address of a backend store, `<scheme>://<endpoint>`,
  comma-separated for multiple backends. Schemes: `ost://host:port` (a
  server speaking the OST wire protocol) and `file:///path` (local
  filesystem). Multiple comma-separated locations mean either mirroring
  (two `ost://`) or data locality (a `file://` cache in front of an
  `ost://` remote). See `docs/locations_and_targets.md`.
- **Target**: a Location with a UUID appended to each URI — addresses one
  specific object, possibly replicated across the backends in the list.
- **OST protocol**: the binary wire protocol `rawstor-ost` speaks and
  `librawstor`'s client implements. Frame layout (magic, command, cid) is
  in `include/rawstor/protocol.h`; the authoritative spec lives in the
  separate `rawstor/rawstor_docs` repo (`Protocol.md`), not in this repo.
- **RawIO**: `librawio`'s internal async I/O abstraction (`rawio::Queue`),
  with two interchangeable backends selected at `configure` time:
  `rawio::uring` (io_uring, default, requires liburing >= 2.3) and
  `rawio::poll` (`poll()`-based fallback, `--without-liburing`). Fully
  C++20-coroutine-based: single-shot ops (`read`/`write`/`accept`/...)
  return a `co_await`-able `Queue::Awaitable<T>`; the 3 multishot ops
  (`poll_multishot`/`accept_multishot`/`recv_multishot`) return a
  pull-stream (`PollStream`/`AcceptStream`/`RecvStream`,
  `include/rawio/stream.hpp`) consumed as `while (auto x = co_await
  stream.next())`. Errors surface uniformly as a thrown
  `std::system_error`. Submission is still eager and the reactor still
  single-threaded/pull-based (`Queue::wait()`/`wait_timeout()` is the only
  thing that drives progress, resuming coroutines inline from inside that
  call) -- `co_await` only attaches a resumption point to an
  already-submitted operation. The public C ABI
  (`include/rawstor/rawio.h`) is unchanged (function-pointer callbacks);
  `librawio/src/rawio.cpp` is a thin coroutine-to-callback adapter over
  the C++ API, using `rawstd::task<T>`/`rawstd::detached_task`
  (`librawstd/include/rawstd/coro.hpp`) under the hood. Each backend keeps
  a per-`Queue` `_dispatch_generation` counter so a multishot registration
  can tell a real new event apart from a same-batch duplicate completion
  (io_uring's `IORING_POLL_ADD_MULTI` and the `poll()` backend can
  otherwise redeliver "readable" more than once per batch for a single
  registration).

## Layout

```
librawstor/
├── librawstd/       internal C++ utility library (logging, endian, iovec, gpp helpers)
├── librawio/         async I/O abstraction (see RawIO above); src/ (impl) + include/rawio/ (public) + tests/
├── src/              core librawstor C++ library (librawstor.la, rawstor.pc); public C API in include/rawstor/
├── include/rawstor/  public C API headers: rawstor.h, object.h, list.h, rawio.h, protocol.h, version.h
├── include/stdheaders/ vendored/trimmed Linux kernel uAPI headers used by vhost/ and vduse/ —
│                     types.h, virtio_types.h, virtio_ring.h, virtio_blk.h, virtio_config.h
│                     (shared by both), vhost_types.h (vhost/ only), vduse.h (vduse/ only); all
│                     kept in one place regardless of how many components use each, rather than
│                     split per-component
├── cli/              rawstor command-line client (create/list/show/remove/testio)
├── ost/              rawstor-ost — the OST protocol server (serves file://, proxies/mirrors to ost://)
├── vhost/             rawstor-vhost — native vhost-user-blk backend (no qemu library dependency)
│   ├── include/vhost/  public headers vhost/tests needs: protocol.h, ring.hpp, virtqueue.hpp
│   ├── src/          device/devregion/ring/server/virtqueue implementation + main.cpp
│   └── tests/         gtest suite (currently: VirtQueue/ring logic)
├── vhost-qemu/       rawstor-vhost-qemu — alternate vhost-user-blk backend built on vendored
│                     qemu libvhost-user (3rdparty/qemu/libvhost-user), kept side-by-side with
│                     vhost/ purely to performance-compare the native vs qemu-library implementation
├── vduse/            rawstor-vduse — VDUSE virtio-blk backend (Linux-only); same include/ +
│                     src/ + tests/ split as vhost/, and like vhost/ implements the protocol
│                     natively (no vendored qemu libvduse or other third-party library)
├── pyrawstor/        Python 3 bindings (location/target helpers)
├── tests/            top-level librawstor integration/unit tests (own in-process test server)
└── docs/             locations_and_targets.md (the OST wire protocol itself is documented
                       upstream in rawstor/rawstor_docs, not here)
```

Most component directories follow the same `src/` + `include/` + `tests/`
split (`librawio`, `vhost`): `src/` holds the implementation and private
headers and builds a `noinst` `.la` (and a binary, where applicable);
`include/` holds only the headers the component's own `tests/` (or other
components) actually need; `tests/` is a self-contained GoogleTest binary
(`test_all`) linked against the `.la`.

## Build

GNU Autotools. C++ code is C++20 (`-std=c++20 -Wall -Wextra -Werror
-fPIC`); C code (`cli/`, `list.c`, `opts.c`) is C99 (`gnu99`).

```
./autogen.sh
./configure --prefix=$HOME/local
make -j$(nproc)
make install
```

Notable `configure` flags:

| Flag | Effect |
|---|---|
| `--enable-debug` / `--enable-trace` | raise `RAWSTD_LOGLEVEL` |
| `--enable-asan` | build with `-fsanitize=address` |
| `--disable-telemetry` | skip collecting/reporting I/O latency/queue-depth stats (collected by default, reported on `rawstor_terminate()`) |
| `--without-liburing` | use librawio's `poll()` backend instead of io_uring |
| `--without-libxxhash` | disable xxhash support |
| `--without-python3` | skip `pyrawstor` |
| `--disable-tests` | skip building all `tests/` subdirs |
| `--disable-ost-backend` | skip building `rawstor-ost` |

liburing must be `>= 2.3` (Ubuntu 22.04's 2.1 is too old and is
unsupported for that reason).

After editing `configure.ac` or any `Makefile.am`, regenerate with
`autoreconf -fi` and re-run `./configure` with the same flags (check
`./config.status --config` to see what was used last) before rebuilding —
`config.status` alone won't pick up new `AC_CONFIG_FILES` entries.

## Testing

```
make test
```

runs `librawstd`, `librawio`, `vhost`, and the top-level `tests/` suites
(and `pyrawstor` if built with Python 3 support), via each subdirectory's
own `make test` target. Test binaries use GoogleTest and are built as
`test_all` in each `tests/` directory; run a single test with
`./tests/test_all --gtest_filter=SuiteName.TestName`.

CI (`.github/workflows/dist.yml`) additionally runs a `clang-format` check
job and builds/tests across the deb/rpm packaging matrix
(Ubuntu 24.04/26.04, AlmaLinux 9/10); `perftest.yml` runs fio-based
performance tests on every push across the `file`/`ost`/`ost-legacy`
backends and the io_uring/poll RawIO backends.

## Code style

- `.clang-format` (LLVM base, 4-space indent, left-aligned pointers).
  Before finishing any C/C++ change, run
  `.github/tools/clang-format.sh` (needs `clang-format-21`, falls back to
  `clang-format`) — it flags files that need re-formatting and prints the
  exact `clang-format -i` command to fix them. Include ordering is part
  of what it enforces (angle-bracket includes sort alphabetically within
  their block).
- Cross-directory includes use angle brackets and are namespaced by
  directory (`<rawio/queue.hpp>`, `<vhost/ring.hpp>`,
  `<rawstd/logging.h>`, `<rawstor/object.h>`); same-directory private
  headers use quotes (`"device.hpp"`).
- Public API headers (`include/rawstor/*.h`) carry an LGPL-3.0 SPDX header
  with copyright; internal implementation files (`src/`, `vhost/src/`,
  etc.) generally don't.
- `namespace rawstor { namespace vhost { ... } }`-style nested namespaces
  (not the C++17 `rawstor::vhost` single-line form) are the existing
  convention in `vhost/`.

## Git conventions

- Use a git worktree for code changes — isolate each task from the main
  checkout and from other work happening concurrently.
- Name the worktree after the branch it holds, replacing `/` with `+`
  (e.g. branch `add/v0.2.7` -> worktree `add+v0.2.7`).
- Branch names: `<type>/<descriptive-name>` — `add/<feature-name>` for new
  features, `fix/<bug-description>` for bug fixes, `ref/<component-name>`
  for refactoring (see README's Contributing section for the full
  contributor workflow: fork, branch, PR).
- Commit subjects: `<type>(<scope>): <summary>`, lowercase, imperative
  mood — observed types across history: `add`, `fix`, `ref`, `docs`,
  `test`, `del`, `debug`. Scope is usually the component directory
  (`vhost`, `librawio`, `ci`, ...) or omitted for repo-wide changes.
- `ChangeLog.md` follows Keep a Changelog; entries go under
  `## [x.y.z] - Unreleased` in the matching `### Added/Changed/Fixed/Removed`
  subsection. `debian/changelog` and the rpm spec changelog are generated
  from it at build time — don't hand-edit them. Only user-visible,
  notable changes earn an entry (new/changed/removed functionality, a bug
  a user could have hit, a packaging change) — not every commit, and not
  internal refactors, test-only changes, or comment/doc tweaks. Keep each
  entry to one short sentence; save the "why" and implementation detail
  for the commit message, not the changelog.
- Never push, including to a new branch. Commit locally and stop there —
  the user reviews what's about to be pushed and pushes it themselves.
- Do not add a `Claude-Session:` (or similar session/tool attribution)
  trailer to commit messages in this repo.

## Gotchas worth knowing

- macOS compatibility matters: everything outside `librawio`'s io_uring
  backend (`uring_queue.*`, inherently Linux-only) should stay buildable
  on macOS, which means `--without-liburing` (the `poll()` backend) there.
  Avoid Linux-only APIs (e.g. `eventfd()`/`<sys/eventfd.h>`, `pipe2()`) in
  portable code and tests — prefer a portable equivalent (e.g. a plain
  `pipe()` + `fcntl(O_NONBLOCK)`) when one exists. For the rare case where
  platform-specific code is genuinely unavoidable, `librawstd/include/
  rawstd/gcc.h` defines `RAWSTD_ON_MACOS`/`RAWSTD_ON_LINUX` for `#if`
  guards — see `librawstd/include/rawstd/endian.h` for the pattern.
- `vhost-qemu/3rdparty/qemu/` is vendored upstream QEMU/libvhost-user
  code. Never patch it — if a bug surfaces there (e.g. `vu_kick_cb()`
  treating a failed `eventfd_read()` as fatal and tearing down the
  kick_fd watch permanently), the fix belongs on rawstor's own side
  (typically in `librawio`), not in the vendored copy. `vhost-qemu`
  exists specifically as a performance/behavior baseline to compare
  `vhost/`'s native implementation against, not as something to extend.
- `vduse/`, unlike `vhost-qemu/`, does not vendor a third-party protocol
  library — it implements the VDUSE control-plane protocol (ioctls on
  `/dev/vduse/control`/`/dev/vduse/$NAME`, IOTLB-backed memory mapping)
  natively, the same way `vhost/` implements vhost-user natively.
  `include/stdheaders/linux/vduse.h` is a trimmed vendored copy of the
  Linux kernel's own uAPI header — if trimming it further, keep any union
  member sharing storage with a field still in use (e.g.
  `vduse_vq_state_packed`, unused since only the split-ring layout is
  implemented), since removing it would shrink the union and shift every
  field the kernel places after it, silently breaking the ioctl ABI.
  VDUSE itself is Linux-only (`--disable-vduse-backend` at `configure`
  time, or auto-disabled on non-Linux hosts) and needs the `vduse` kernel
  module plus `/dev/vduse/control` access at runtime — see the top-level
  README's "rawstor-vduse" section.
- virtio `EVENT_IDX` is a *bidirectional* suppression handshake:
  `used_event` (driver→device, suppresses interrupts) and `avail_event`
  (device→driver, suppresses kicks) are independent and both must be
  published by the device side, or the driver can stop kicking
  permanently once it believes no one is listening.
- A multishot poll registration (io_uring `IORING_POLL_ADD_MULTI`, or the
  `poll` backend's multishot path) can legitimately deliver more than one
  "readable" completion per reap batch for the same fd (e.g. an eventfd
  written to multiple times before it's drained) — a stream consumer
  (`while (auto x = co_await stream.next())`) that reacts to every
  completion as if it were a fresh event can observe a drained resource
  (e.g. `EAGAIN` on `eventfd_read()`) and misbehave. This is what
  `_dispatch_generation` (see RawIO above) exists to prevent; keep it in
  mind when adding new multishot call sites.
- This is a shared-checkout environment: other sessions/the maintainer
  may commit and push to the same branches concurrently. Re-check
  `git log`/`git status` before assuming a branch's tip is still what you
  last saw.
