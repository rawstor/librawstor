# Rawstor library and tools

[![Unit Test Status](https://github.com/rawstor/librawstor/actions/workflows/dist.yml/badge.svg)](https://github.com/rawstor/librawstor/actions/workflows/dist.yml)

## TL;DR
```
PREFIX=${HOME}/local

./autogen.sh
./configure --prefix=${PREFIX}
make -j$(nproc)
make install

OST_ADDR=192.168.0.1:7777

##
# OST Server
#
OST_DATADIR=/var/rawstor

mkdir -p ${OST_DATADIR}

rawstor-ost \
    --bind ${OST_ADDR} \
    file://${OST_DATADIR}

##
# Client
#
OBJECT_TARGET=$(rawstor create ost://${OST_ADDR} --size=1G)

VHOST_RUNDIR=${PREFIX}/var/run/rawstor

mkdir -p ${VHOST_RUNDIR}

rawstor-vhost \
    --socket-path=${VHOST_RUNDIR}/rawstor1.sock \
    ${OBJECT_TARGET}

qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -machine accel=kvm,memory-backend=mem \
    -drive file=image.qcow2,if=none,id=drive1 \
    -device virtio-blk-pci,drive=drive1 \
    -object memory-backend-memfd,id=mem,size=4G,share=on \
    -chardev socket,id=rawstor1,reconnect=1,path=${VHOST_RUNDIR}/rawstor1.sock \
    -device vhost-user-blk-pci,chardev=rawstor1,num-queues=1,disable-legacy=on
```

## Environment Variables

The following environment variables can be used to tune the behavior of the Rawstor client and server.
Default values are shown below.

| Variable | Default | Description |
|----------|---------|-------------|
| `RAWSTOR_LOCATION` | *(none)* | Fallback `LOCATION` for `rawstor create`/`list`/`info` when it's omitted from the command line. |
| `RAWSTOR_OPTS_IO_ATTEMPTS` | `3` | Number of retry attempts for an I/O operation the backend itself rejected (a well-formed response reporting a failure, e.g. `EBUSY`/`ENOSPC`) -- the connection is fine, so these retry against the same session. A backend rejection known to never succeed on retry (e.g. `ENOENT`) isn't retried at all, regardless of this value. Doesn't govern reconnects after a broken connection -- see `RAWSTOR_OPTS_IO_WIRE_RETRY_ATTEMPTS`. |
| `RAWSTOR_OPTS_IO_WIRE_RETRY_ATTEMPTS` | `3` | Number of reconnect+retry attempts after losing the connection to the backend entirely (couldn't connect, connection reset, corrupt/unexpected data on the wire) -- as opposed to `RAWSTOR_OPTS_IO_ATTEMPTS` above, which governs a rejection *from* a live connection instead. `rawstor-vhost`/`rawstor-vduse`'s packaged systemd units raise this to effectively unlimited (`-1`, parsed as a very large number), matching how a QEMU vhost-user chardev's own `reconnect=N` keeps retrying forever -- the network can come back at any time, and the guest should stall rather than see a stream of spurious I/O errors for a blip. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE` | `100` | Base delay, in milliseconds (ms), before the first retry of an I/O operation; doubles with each further attempt, capped at `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX`. Applies to both kinds of retry above. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX` | `2000` | Upper bound, in milliseconds (ms), on the exponential retry backoff delay above. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER` | `50` | Percentage (0-100, not a time value) of the computed retry backoff delay that is randomized, to avoid many clients retrying in lockstep. `0` disables jitter (a plain exponential backoff); `100` is "Full Jitter" (the whole delay is randomized); `50` is "Equal Jitter" (half the delay is fixed, half is randomized). |
| `RAWSTOR_OPTS_SESSIONS` | `1` | Number of concurrent sessions that Rawstor client will open for each object. |
| `RAWSTOR_OPTS_SO_SNDTIMEO` | `5000` | Socket send timeout, in milliseconds (ms). Sets `SO_SNDTIMEO` for network sockets. |
| `RAWSTOR_OPTS_SO_RCVTIMEO` | `5000` | Socket receive timeout, in milliseconds (ms). Sets `SO_RCVTIMEO` for network sockets. |
| `RAWSTOR_OPTS_TCP_USER_TIMEOUT` | `5000` | TCP user timeout, in milliseconds (ms) (Linux `TCP_USER_TIMEOUT`). Defines how long transmitted data may remain unacknowledged before the connection is closed. |
| `RAWSTOR_OPTS_LIST_LIMIT` | `1000` | Server-side page size cap for list operations: the maximum number of objects returned in a single call, regardless of the caller-requested limit. Larger listings are paginated across multiple calls. |
| `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` | `128` | Per-session cap on writes dispatched to a `file://` backing store without their completion arriving yet; writes past the cap wait for a dispatch slot instead of being sent immediately. |
| `RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY` | `256M` | Per-session cap on writes queued behind `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` but not yet dispatched to a `file://` backing store; a write that would push the backlog over the cap fails with `EBUSY` instead of queuing. Takes either a plain byte count or a size with a unit suffix (`B`, `K`, `M`, `G`, `T`, `P`, `E`), e.g. `256M`. |

> **Note:** All timeout values are expressed in milliseconds unless stated otherwise.

## rawstor-ost – OST Protocol Server

`rawstor-ost` implements the **OST protocol** (see [Protocol.md](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md)), handling network connections and providing access to data stored in **locations** (as defined in the [Locations and Targets](https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md) documentation).

- `file://` scheme → serves data directly from the local filesystem.
- `ost://` scheme → acts as a proxy to an underlying OST backend.
- Comma‑separated list → supports mirroring or data locality.

### Usage

`rawstor-ost [-h] -b ADDR LOCATION`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `LOCATION` | Comma‑separated list of backend locations (e.g., `file:///path`, `ost://host:port`). |
| `-b, --bind ADDR` | Bind address in `<ip>:<port>` format (e.g., `127.0.0.1:7777`). |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket (default: `12`). |

### Examples

Serve local directory:
```bash
rawstor-ost -b 0.0.0.0:7777 file:///var/rawstor/data
```

Proxy to remote OST:
```bash
rawstor-ost -b 0.0.0.0:7777 ost://192.168.1.100:7777
```

Data locality (local cache + proxy):
```bash
rawstor-ost -b 0.0.0.0:7777 file:///var/rawstor/data,ost://remote:7777
```

Mirroring between two OST backends:
```bash
rawstor-ost -b 0.0.0.0:7777 ost://left:7777,ost://right:7777
```

## rawstor-vhost – vhost-user-blk Backend

`rawstor-vhost` is a userspace VirtIO block device backend implementing the
[vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html)
for `virtio-blk-pci`/`vhost-user-blk-pci` devices. It gives a guest direct,
zero-copy access to a rawstor object's data: virtqueue descriptors are
resolved straight into the guest's shared memory regions and read from or
written to the backing object via `librawstor`'s native `io_uring`-based
object I/O, with no host-side kernel block layer or copy in between.

The vhost-user protocol itself (feature/memory-region negotiation,
virtqueue kick/call handling, request dispatch) is implemented natively in
`vhost/` — it does not depend on qemu's `libvhost-user` library. Every I/O
path, including the control socket, is asynchronous and non-blocking, and
multiple in-flight requests on a virtqueue may complete out of order.

### Usage

`rawstor-vhost [-h] -s SOCKET_PATH TARGET [--queue-size SIZE] [--num-queues N] [--write-cache on|off] [-v]`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-s, --socket-path PATH` | Location of the vhost-user Unix domain socket. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Locations and Targets](https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth of each virtqueue's own queue. Default: `256`. |
| `--num-queues N` | Number of virtqueues advertised to the guest, each serviced by its own thread and its own connection to `TARGET`. The guest picks how many of these it actually uses (typically up to its vCPU count) via QEMU's own `num-queues=`. Default: `16`. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest; write-through makes every write durable on completion, writeback relies on the guest issuing an explicit flush. |
| `-v, --version` | Print version and exit. |

### Example

```
PREFIX=${HOME}/local
OST_ADDR=192.168.0.1:7777
OBJECT_ID=...
VHOST_RUNDIR=${PREFIX}/var/run/rawstor

rawstor-vhost \
    --socket-path=${VHOST_RUNDIR}/rawstor1.sock \
    ost://${OST_ADDR}/${OBJECT_ID}

qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -machine accel=kvm,memory-backend=mem \
    -drive file=image.qcow2,if=none,id=drive1 \
    -device virtio-blk-pci,drive=drive1 \
    -object memory-backend-memfd,id=mem,size=4G,share=on \
    -chardev socket,id=rawstor1,reconnect=1,path=${VHOST_RUNDIR}/rawstor1.sock \
    -device vhost-user-blk-pci,chardev=rawstor1,num-queues=1,disable-legacy=on
```

### Supported virtio-blk features

`rawstor-vhost` negotiates `VIRTIO_BLK_F_SIZE_MAX`, `VIRTIO_BLK_F_SEG_MAX`,
`VIRTIO_BLK_F_BLK_SIZE`, `VIRTIO_BLK_F_TOPOLOGY`, `VIRTIO_BLK_F_MQ`,
`VIRTIO_BLK_F_FLUSH`, `VIRTIO_BLK_F_CONFIG_WCE`, `VIRTIO_BLK_F_DISCARD`,
`VIRTIO_BLK_F_WRITE_ZEROES`, `VIRTIO_RING_F_INDIRECT_DESC` and
`VIRTIO_RING_F_EVENT_IDX`, and services read (`VIRTIO_BLK_T_IN`), write
(`VIRTIO_BLK_T_OUT`), flush (`VIRTIO_BLK_T_FLUSH`), discard
(`VIRTIO_BLK_T_DISCARD`), write-zeroes (`VIRTIO_BLK_T_WRITE_ZEROES`) and
identify (`VIRTIO_BLK_T_GET_ID`) requests. A flush is device-wide: since
each virtqueue has its own connection to `TARGET` (see below), a
`VIRTIO_BLK_T_FLUSH` arriving on one makes durable every write issued
through *any* of them, not just its own. `VIRTIO_BLK_F_MQ` is negotiated
and genuinely serviced: `rawstor-vhost` advertises up to `--num-queues`
virtqueues (a front-end learns the count via `VHOST_USER_GET_QUEUE_NUM`),
each processed on its own thread and its own connection to `TARGET` in
parallel.

### Notes

`rawstor-vhost` serves exactly one front-end connection per process
invocation: it accepts a connection on the socket, serves it until the
front-end disconnects (exiting cleanly), and then exits. A setup or
protocol error (e.g. a mismatched `num-queues`) is reported and also exits
the process, rather than silently waiting for another connection. Pair it
with `reconnect=1` on the QEMU chardev and an external supervisor (e.g.
`systemd` with `Restart=always`, or a wrapper loop) if the backend needs to
survive guest-side reconnects. Send `SIGINT`/`SIGTERM` to stop it.

### Packaging and QEMU access

`rawstor-vhost` ships in its own `rawstor-vhost` deb/rpm package (separate
from `librawstor`), along with the `rawstor-vhost@.service` systemd
template unit. The package creates the same system user/group (`rawstor`)
that `rawstor-ost` uses, if it doesn't already exist — it does **not**
depend on `libvirt`, since `rawstor-vhost` has no need for it (it talks to
QEMU purely over a vhost-user Unix socket, negotiated when QEMU connects).

Whatever user actually runs QEMU (`libvirt-qemu` on Debian/Ubuntu, `qemu`
on Fedora/RHEL, or something else entirely if you invoke QEMU by hand)
needs permission to connect to the socket under `RuntimeDirectory=rawstor`
(`/run/rawstor/*.sock`). Add that user to the `rawstor` group rather than
running `rawstor-vhost` as it:

```bash
sudo usermod -aG rawstor libvirt-qemu   # Debian/Ubuntu + libvirt
sudo usermod -aG rawstor qemu           # Fedora/RHEL + libvirt
```

This works because `rawstor-vhost` `chmod()`s the socket to `0660` itself
right after creating it, regardless of the caller's umask — on Linux,
`connect(2)` to a UNIX stream socket requires *write* permission on the
socket file itself (not just directory access), so leaving it at whatever
`bind(2)` produced under the process's umask (commonly `0755`, i.e.
group gets read+execute but no write) would silently prevent anyone but
the socket's owner from ever connecting. Since the daemon enforces this
itself, it holds regardless of how or by whom `rawstor-vhost` is invoked —
including if you override `User=`/`Group=` below via a drop-in.

If `User=`/`Group=rawstor` in the unit doesn't fit your setup (e.g. you'd
rather run `rawstor-vhost` as the same user QEMU runs as, instead of
sharing access via the group), override it with a drop-in instead of
editing the shipped unit file — `systemctl edit rawstor-vhost@.service`
(all instances) or `systemctl edit rawstor-vhost@<uuid>.service` (one
instance) opens an editor and saves the result under
`/etc/systemd/system/…/override.conf`, which survives package upgrades.
See the comment above `User=` in `systemd/rawstor-vhost@.service` and
`systemd.unit(5)` for details.

## rawstor-vduse – VDUSE virtio-blk Backend

`rawstor-vduse` is a userspace VirtIO block device backend implementing the
[VDUSE](https://docs.kernel.org/userspace-api/vduse.html) (vDPA Device in
Userspace) protocol for `virtio-blk` devices. Unlike `rawstor-vhost`
(vhost-user, a QEMU-only Unix-socket protocol), VDUSE creates a real kernel
vDPA device: once attached to the vDPA bus, it can be driven either by
`virtio-vdpa` (the guest's virtio-blk driver talks to the kernel vDPA
framework directly -- no VMM involved at all, e.g. for containers) or by
`vhost-vdpa` (a VMM such as QEMU drives it through `/dev/vhost-vdpa-N`).

The VDUSE control-plane protocol (device/virtqueue setup via ioctl(2) on
`/dev/vduse/control` and `/dev/vduse/$NAME`, IOTLB-backed memory mapping,
kick/interrupt handling) is implemented natively in `vduse/` -- like
`vhost/`, it does not vendor or link against any third-party protocol
library (qemu's `libvduse` included); only the kernel uAPI struct/ioctl
definitions themselves are vendored (`vduse/include/stdheaders/linux/`,
trimmed the same way `vhost/include/stdheaders/` vendors its own kernel
headers). Every I/O path, including the control channel, is asynchronous
and non-blocking via RawIO, and multiple in-flight requests on a virtqueue
may complete out of order -- the same design `vhost/` uses for
vhost-user.

### Usage

`rawstor-vduse [-h] TARGET [--queue-size SIZE] [--num-queues N] [--write-cache on|off] [-v]`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Locations and Targets](https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md)). Creates `/dev/vduse/UUID`, where `UUID` is the target object's own UUID -- there is no separate name to pick, since the UUID already uniquely and stably identifies it. |
| `--queue-size SIZE` | Virtqueue size, a power of two, of each virtqueue's own queue. Default: `256`, max `1024`. |
| `--num-queues N` | Number of virtqueues advertised to the guest, each serviced by its own thread and its own connection to `TARGET`. Default: `16`. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest. |
| `-v, --version` | Print version and exit. |

### Example

```
OST_ADDR=192.168.0.1:7777
OBJECT_ID=...

sudo modprobe vduse

sudo rawstor-vduse \
    ost://${OST_ADDR}/${OBJECT_ID} &

# Attach the device to the vDPA bus once rawstor-vduse has created it
# (named after OBJECT_ID, i.e. /dev/vduse/${OBJECT_ID}):
sudo vdpa dev add name ${OBJECT_ID} mgmtdev vduse

# Either hand it to a guest's virtio-vdpa driver directly (no VMM), or
# drive it from QEMU over /dev/vhost-vdpa-N:
qemu-system-x86_64 \
    -enable-kvm \
    -m 4G \
    -device vhost-vdpa-device-pci,vhostdev=/dev/vhost-vdpa-0
```

### Supported virtio-blk features

`rawstor-vduse` negotiates `VIRTIO_BLK_F_SEG_MAX`, `VIRTIO_BLK_F_BLK_SIZE`,
`VIRTIO_BLK_F_TOPOLOGY`, `VIRTIO_BLK_F_FLUSH`, `VIRTIO_BLK_F_MQ`,
`VIRTIO_BLK_F_DISCARD`, `VIRTIO_BLK_F_WRITE_ZEROES`, plus whatever baseline
virtio/ring features the kernel VDUSE driver itself requires
(`VIRTIO_F_VERSION_1`, `VIRTIO_F_ACCESS_PLATFORM`,
`VIRTIO_F_NOTIFY_ON_EMPTY`, `VIRTIO_RING_F_EVENT_IDX`,
`VIRTIO_RING_F_INDIRECT_DESC`), and services read (`VIRTIO_BLK_T_IN`), write
(`VIRTIO_BLK_T_OUT`), flush (`VIRTIO_BLK_T_FLUSH`), discard
(`VIRTIO_BLK_T_DISCARD`), write-zeroes (`VIRTIO_BLK_T_WRITE_ZEROES`) and
identify (`VIRTIO_BLK_T_GET_ID`) requests. A flush is device-wide: since
each virtqueue has its own connection to `TARGET` (see below), a
`VIRTIO_BLK_T_FLUSH` arriving on one makes durable every write issued
through *any* of them, not just its own. `VIRTIO_BLK_F_MQ` is negotiated
and genuinely serviced: `rawstor-vduse` advertises up to `--num-queues`
virtqueues, each processed on its own thread and its own connection to
`TARGET` in parallel.

Unlike vhost-user, VDUSE has no driver-writable config space at all --
there is no protocol message equivalent to `VHOST_USER_SET_CONFIG` -- and
the kernel VDUSE driver unconditionally rejects `VIRTIO_BLK_F_CONFIG_WCE`
for virtio-blk devices (device creation fails outright if it's
advertised), so `rawstor-vduse` doesn't negotiate it. `--write-cache`
still works: Linux's `virtio_blk` driver enables its write-cache
(flush-before-trusting-durability) assumption whenever
`VIRTIO_BLK_F_FLUSH` is negotiated regardless of `CONFIG_WCE`, so the
guest always issues `FLUSH` appropriately either way -- the flag purely
controls whether `rawstor-vduse` itself additionally makes every write
durable on completion or relies solely on that `FLUSH`.

### Notes

`rawstor-vduse` creates one VDUSE device per process invocation and keeps
running until the process is stopped (`SIGINT`/`SIGTERM`) or the VDUSE
device itself is destroyed out from under it -- unlike `rawstor-vhost`,
there is no per-connection front-end to disconnect from, since the kernel
is always "connected". Attaching the created device to the vDPA bus (`vdpa
dev add name UUID mgmtdev vduse`) and, if applicable, driving it from a
VMM, are separate, external steps. If the process is restarted while
requests are in flight, it does not attempt to resubmit them (no
inflight-request log is kept) -- a crash mid-request is visible to the
guest as that request never completing, the same failure mode a guest
already has to tolerate from a host crash.

### Packaging and access

`rawstor-vduse` ships in its own `rawstor-vduse` deb/rpm package (separate
from `librawstor`), along with the `rawstor-vduse@.service` systemd
template unit and a udev rule granting the `rawstor` system user/group
(shared with `rawstor-ost`/`rawstor-vhost`) access to `/dev/vduse/control`
and the device nodes it creates under `/dev/vduse/`.

Creating a VDUSE device requires the `vduse` kernel module (`modprobe
vduse`), and attaching it to the vDPA bus requires the `vdpa` tool
(`iproute2`) and `CAP_NET_ADMIN` -- neither is something `rawstor-vduse`
itself does; both are external, one-time-per-device administrative steps.

## Testing

```
make test
```

## Contributing

We love your contributions and want to make it as easy as possible to work together. Please follow these guidelines when contributing to this project.

### Before You Start

For major features or significant changes, please open an issue first to discuss your proposed changes with the maintainers. This helps ensure your work aligns with the project direction and prevents duplicate effort.
For small fixes (typos, minor bugs), feel free to open a pull request directly.

### Development Workflow

1. Fork the repository on GitHub

2. Clone your fork locally:

```bash
git clone https://github.com/<your-username>/librawstor.git
cd librawstor
```

3. Create a feature branch with a descriptive name:

```bash
# For new features:
git checkout -b add/feature-name

# For bug fixes:
git checkout -b fix/bug-description

# For refactoring:
git checkout -b ref/component-name
```

4. Make your changes and commit them with clear, descriptive commit messages

5. Push your branch to your fork:

```bash
git push origin <your-branch-name>
```

6. Submit a Pull Request from your branch to the `main` branch of the `rawstor/librawstor` repository

### Code Style & Standards

* Follow the existing code style and patterns in the project
* Write clear, descriptive commit messages
* Include comments for complex logic
* Update documentation when necessary
* Add tests for new functionality

### Pull Request Guidelines

* Provide a clear description of what the PR accomplishes
* Reference any related issues (e.g., "Fixes #123")
* Ensure all tests pass (by running `make test`) and code meets quality standards
* Keep PRs focused on a single purpose - avoid mixing multiple features

### Need Help?

* Check existing issues and discussions
* Ask questions in the project's GitHub Discussions
* Reach out to maintainers by mentioning them in issues

Thank you for contributing!

## Troubleshooting

### Operation not permitted
```
io_uring_queue_init() failed: Operation not permitted
```

First check if `io_uring` is disabled or not in `sysctl`:
```bash
sysctl -a | grep io_uring
```

According to the documentation for the `sysctl` files in `/proc/sys/kernel/`:

> `io_uring_disabled`:
>
> Prevents all processes from creating new `io_uring` instances. Enabling this shrinks the kernel’s attack surface.
>
> `0` - All processes can create `io_uring` instances as normal. This is the default setting.
>
> `1` - `io_uring` creation is disabled (`io_uring_setup()` will fail with `-EPERM`) for unprivileged processes not in the `io_uring_group` group. Existing `io_uring` instances can still be used. See the documentation for `io_uring_group` for more information.
>
> `2` - `io_uring` creation is disabled for all processes. `io_uring_setup()` always fails with `-EPERM`. Existing `io_uring` instances can still be used.

So you need to set it to 0:

```bash
sysctl kernel.io_uring_disabled=0
```
