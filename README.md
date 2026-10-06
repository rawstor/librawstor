# Rawstor library and tools

[![Unit Test Status](https://github.com/rawstor/librawstor/actions/workflows/dist.yml/badge.svg)](https://github.com/rawstor/librawstor/actions/workflows/dist.yml)

> 📖 **Documentation:**
> [Concepts](docs/concepts.md) ·
> [Architecture](docs/architecture.md) ·
> [Protocol](docs/protocol.md) ·
> [MDS design](docs/mds.md) ·
> [Mirroring](docs/mirroring.md)

## TL;DR
```
PREFIX=${HOME}/local

./autogen.sh
./configure --prefix=${PREFIX}
make -j$(nproc)
make install

OST_ADDR=192.168.0.1:7777
MDS_ADDR=192.168.0.1:7776

##
# OST Server
#
OST_DATADIR=/var/rawstor

mkdir -p ${OST_DATADIR}

rawstor-ost \
    --bind ${OST_ADDR} \
    file://${OST_DATADIR}

##
# MDS Server (optional: only for chunked mds:// objects)
#
MDS_DATADIR=/var/lib/rawstor/mds

mkdir -p ${MDS_DATADIR}

# One line per OST: <uuid> <location> <weight> [[[<dc>/]<row>/]<rack>/]<server>
cat > ${MDS_DATADIR}/topology.conf <<EOF
$(cat /proc/sys/kernel/random/uuid) ost://${OST_ADDR} 100 dc1/row1/rack1/host1
EOF

rawstor-mds \
    --bind ${MDS_ADDR} \
    --db ${MDS_DATADIR}/mds.db \
    --topology ${MDS_DATADIR}/topology.conf

##
# Client
#
# An object split into 256M chunks, placed across the OSTs by the MDS...
OBJECT_TARGET=$(rawstor create mds://${MDS_ADDR} --size=1G --chunk-size=256M --mirrors=1)
# ...or a plain object stored whole on one OST, no MDS needed:
# OBJECT_TARGET=$(rawstor create ost://${OST_ADDR} --size=1G --mirrors=1)

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
| `RAWSTOR_MDS_OPTS_INFO_INTERVAL` | `300000` | MDS backend INFO/health polling interval in milliseconds; each OST is polled once per interval at its own fixed offset, spreading probes evenly. Must be positive. |
| `RAWSTOR_MDS_OPTS_INFO_CONCURRENCY` | `128` | Maximum concurrent MDS backend probes, including retries (1–1024); see [MDS health and location information](docs/mds.md#backend-health-and-location-information). |
| `RAWSTOR_OPTS_IO_ATTEMPTS` | `10` | Number of attempts for an I/O operation before giving up, covering any failure from a broken connection to a well-formed rejection from a live backend (e.g. `EBUSY`/`ENOSPC`) -- every retry reconnects first (except a plain `EBUSY`, where the session is fine and just backed up against the remote server's own write-throttling). A rejection known to never succeed on retry (e.g. `ENOENT`) isn't retried at all, regardless of this value. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE` | `100` | Base delay, in milliseconds (ms), before the first retry of an I/O operation; doubles with each further attempt, capped at `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX`. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX` | `30000` | Upper bound, in milliseconds (ms), on the exponential retry backoff delay above. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER` | `50` | Percentage (0-100, not a time value) of the computed retry backoff delay that is randomized, to avoid many clients retrying in lockstep. `0` disables jitter (a plain exponential backoff); `100` is "Full Jitter" (the whole delay is randomized); `50` is "Equal Jitter" (half the delay is fixed, half is randomized). |
| `RAWSTOR_OPTS_SESSIONS` | `1` | Number of concurrent sessions that Rawstor client will open for each object. |
| `RAWSTOR_OPTS_SO_SNDTIMEO` | `5000` | Socket send timeout, in milliseconds (ms). Sets `SO_SNDTIMEO` for network sockets. |
| `RAWSTOR_OPTS_SO_RCVTIMEO` | `5000` | Socket receive timeout, in milliseconds (ms). Sets `SO_RCVTIMEO` for network sockets. |
| `RAWSTOR_OPTS_TCP_USER_TIMEOUT` | `5000` | TCP user timeout, in milliseconds (ms) (Linux `TCP_USER_TIMEOUT`). Defines how long transmitted data may remain unacknowledged before the connection is closed. |
| `RAWSTOR_OPTS_LIST_LIMIT` | `1000` | Server-side page size cap for list operations: the maximum number of objects returned in a single call, regardless of the caller-requested limit. Larger listings are paginated across multiple calls. |
| `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` | `128` | Per-session cap on writes dispatched to a `file://` backing store without their completion arriving yet; writes past the cap wait for a dispatch slot instead of being sent immediately. |
| `RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY` | `256M` | Per-session cap on writes queued behind `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` but not yet dispatched to a `file://` backing store; a write that would push the backlog over the cap fails with `EBUSY` instead of queuing. Takes a size with a mandatory unit suffix (`B`, `K`, `M`, `G`, `T`, `P`, `E`), e.g. `256M` or `4096B`; a bare number is rejected. |

> **Note:** All timeout values are expressed in milliseconds unless stated otherwise.

An unset variable takes its default. A set one must be valid -- a plain
decimal integer within the variable's range (or, for a size, a number with a
unit) -- otherwise the program logs the variable and the accepted range and
exits with `EX_CONFIG` (78), which the shipped systemd units do not restart.
`0` is accepted only where it means something: it disables
`RAWSTOR_OPTS_SO_SNDTIMEO`, `RAWSTOR_OPTS_SO_RCVTIMEO`,
`RAWSTOR_OPTS_TCP_USER_TIMEOUT` and the retry backoff, and allows no backlog in
`RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY`.

## rawstor-ost – OST Protocol Server

`rawstor-ost` implements the **OST protocol** (see [Protocol](https://github.com/rawstor/librawstor/blob/main/docs/protocol.md)), handling network connections and providing access to data stored in **locations** (as defined in the [Concepts](https://github.com/rawstor/librawstor/blob/main/docs/concepts.md) documentation).

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

### systemd instances

The `rawstor-ost` deb/rpm package ships the `rawstor-ost@.service`
template: one instance per OST, named after the OST's id (the `<uuid>` the
MDS topology lists it under), configured by
`/etc/rawstor/ost/<uuid>.conf`. Installing the package starts nothing; an
instance without its config refuses to start. A host runs as many
instances as it has OSTs, each on its own port and store.

The config is an environment file (`KEY=VALUE` lines):

| Key | Default | Description |
|-----|---------|-------------|
| `BIND_ADDR` | — (required) | `<ip>:<port>` to listen on, unique per host. |
| `LOCATION` | `file:///var/lib/rawstor/ost/<uuid>` | Backing store this instance serves. |
| `QUEUE_SIZE` | `4096` | `--queue-size`. |
| `WORKERS` | `12` | `--workers`. |
| `RAWSTOR_OPTS_*` | | Tuning knobs, see [Environment Variables](#environment-variables). |

The instance runs as the `rawstor` user under `ProtectSystem=strict`. Its
default store, `/var/lib/rawstor/ost/<uuid>` (`StateDirectory=`), is
created on start and owned by `rawstor`; a disk mounted there needs no
further configuration. A store anywhere else needs a per-instance drop-in
granting the sandbox access to it, and must be writable by `rawstor`:

```bash
sudo systemctl edit rawstor-ost@<uuid>.service
# [Service]
# ReadWritePaths=/srv/disk1/rawstor
```

Two OSTs on one host:

```bash
OST1=$(cat /proc/sys/kernel/random/uuid)
OST2=$(cat /proc/sys/kernel/random/uuid)
echo "BIND_ADDR=0.0.0.0:7777" | sudo tee /etc/rawstor/ost/${OST1}.conf
echo "BIND_ADDR=0.0.0.0:7778" | sudo tee /etc/rawstor/ost/${OST2}.conf
sudo systemctl enable --now rawstor-ost@${OST1} rawstor-ost@${OST2}

systemctl status rawstor-ost@${OST1}       # state
journalctl -u rawstor-ost@${OST1}          # log
rawstor info ost://127.0.0.1:7777          # serving?
sudo systemctl restart rawstor-ost@${OST1}
```

Removing an instance never touches its store: stop and disable it, then
delete its config. Recreating the same config later serves the same data
again; the store itself is removed by hand, if at all.

```bash
sudo systemctl disable --now rawstor-ost@${OST2}
sudo rm /etc/rawstor/ost/${OST2}.conf
# data stays in /var/lib/rawstor/ost/${OST2}
```

A package upgrade restarts the running instances; removing the package
stops them, leaving configs, stores and enablement in place.

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

`rawstor-vhost [-h] -s SOCKET_PATH TARGET [--queue-size SIZE] [--write-cache on|off] [--readonly] [-v]`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-s, --socket-path PATH` | Location of the vhost-user Unix domain socket. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Concepts](https://github.com/rawstor/librawstor/blob/main/docs/concepts.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth of each virtqueue's own queue. Default: `4096`. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest; write-through makes every write durable on completion, writeback relies on the guest issuing an explicit flush. |
| `--readonly` | Export the object read-only: advertises `VIRTIO_BLK_F_RO` to the guest and opens `TARGET` with `RAWSTOR_READONLY` (no mirror write quorum needed; writes fail). Required to export a version target. |
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
and genuinely serviced: the front-end alone decides how many virtqueues
to use (QEMU's own `num-queues=`, which defaults to the guest's vCPU
count; `rawstor-vhost` reports up to 1024 via `VHOST_USER_GET_QUEUE_NUM`),
and each one it sets up is processed on its own thread and its own
connection to `TARGET` in parallel, started the first time the front-end
configures that queue.

### Notes

`rawstor-vhost` serves exactly one front-end connection per process
invocation: it accepts a connection on the socket, serves it until the
front-end disconnects (exiting cleanly), and then exits. A setup or
protocol error (e.g. failing to connect a new virtqueue to `TARGET`) is reported and also exits
the process, rather than silently waiting for another connection. Pair it
with `reconnect=1` on the QEMU chardev and an external supervisor (e.g.
`systemd` with `Restart=always`, or a wrapper loop) if the backend needs to
survive guest-side reconnects. Send `SIGINT`/`SIGTERM` to stop it: it
first waits for every request already in flight to complete, so QEMU,
reconnecting to the restarted backend, carries on exactly where it left
off. It also negotiates `VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD`: every
request is logged in shared memory QEMU keeps across backend restarts, so
after a crash the restarted backend resubmits whatever was left in
flight, in its original order.

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

`rawstor-vduse [-h] TARGET [--queue-size SIZE] [--num-queues N] [--write-cache on|off] [--readonly] [-v]`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Concepts](https://github.com/rawstor/librawstor/blob/main/docs/concepts.md)). Creates `/dev/vduse/UUID`, where `UUID` is the target object's own UUID -- there is no separate name to pick, since the UUID already uniquely and stably identifies it. |
| `--queue-size SIZE` | Virtqueue size, a power of two, of each virtqueue's own queue. Default: `256`, max `1024`. |
| `--num-queues N` | Number of virtqueues advertised to the guest. Each one the driver actually enables is serviced by its own thread and its own connection to `TARGET`, started at that point (Linux's `virtio_blk` enables up to its CPU count). Default: the host's number of CPUs. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest. |
| `--readonly` | Export the object read-only: advertises `VIRTIO_BLK_F_RO` to the guest and opens `TARGET` with `RAWSTOR_READONLY` (no mirror write quorum needed; writes fail). Required to export a version target. |
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
and genuinely serviced: `rawstor-vduse` advertises `--num-queues`
virtqueues, and each one the driver enables is processed on its own
thread and its own connection to `TARGET` in parallel.

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
VMM, are separate, external steps.

On `SIGINT`/`SIGTERM` it first waits for every request already in flight
to complete. A device still bound to the vDPA bus outlives the process; a
restarted `rawstor-vduse` reattaches to it and, if the driver is already
using it, resumes every ready virtqueue where the previous instance left
off, without the driver noticing -- as long as it is back within the
kernel's VDUSE message timeout (`/sys/class/vduse/UUID/msg_timeout`, 30 s
by default), after which the kernel marks the device broken. Requests in
flight during a crash are resubmitted too: every request is logged, in
the same format as vhost-user's in-flight memory, in
`/dev/shm/rawstor-vduse-UUID.inflight`, a tmpfs file that outlives the
process but not a reboot (which takes the VDUSE device with it anyway),
and is removed along with the device. A reattached device keeps the
virtqueue count it was created with, so `--num-queues` must not change
across restarts.

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

## rawstor-mds – Metadata Server

`rawstor-mds` is the metadata server behind `mds://<host>:<port>/<uuid>`
targets: a logical object split into fixed-size chunks, each independently
placed (and optionally mirrored) across a static OST topology, opened/
read/written through the same `rawstor_target_*()`/`rawstor` CLI surface
as a plain object (see [MDS design](https://github.com/rawstor/librawstor/blob/main/docs/mds.md)). A single instance owns the explicit
chunk map (SQLite, WAL journal) and the static topology config for its own
cluster; it is not in the data path -- `rawstor_target_open()` talks to
the placed OSTs directly once it has resolved an object's own chunk map.

### Usage

`rawstor-mds [options] -b ADDR -d DBPATH -t TOPOLOGY`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-b, --bind ADDR` | Bind address in `<ip>:<port>` format (e.g., `127.0.0.1:7776`). |
| `-d, --db PATH` | SQLite database file holding the chunk map (created if missing). |
| `-t, --topology PATH` | Static topology config file: one `<uuid> <location> <weight> [[[<dc>/]<row>/]<rack>/]<server>` line per OST (failure domains from the root down; only `<server>` is required), `<location>` being a single location URI (`ost://host:port`; a client-local one such as `file://` only makes sense on a single host; to put several stores under one entry, list a `rawstor-ost` serving them all) (see [MDS design](https://github.com/rawstor/librawstor/blob/main/docs/mds.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth. Default: `4096`. |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket and sharing one database (default: `4`). |
| `-r, --reconstruct` | Rebuild the chunk map from a LIST+META scan of every OST in the topology before serving -- for recovering from a lost or corrupted database. |

### Examples

Serve a topology of two OSTs:
```bash
cat > topology.conf <<EOF
018f4e2a-1000-7000-8000-000000000001 ost://host1:7777 100 dc1/row1/rack1/host1
018f4e2a-1000-7000-8000-000000000002 ost://host2:7777 100 dc1/row1/rack1/host2
EOF
rawstor-mds -b 0.0.0.0:7776 -d /var/lib/rawstor/mds/mds.db -t topology.conf
```

Create and grow an `mds://` object:
```bash
rawstor create -t mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=1G --chunk-size=256M --mirrors=1
rawstor resize mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=2G
```

Add an OST: append its line to `topology.conf` and send `SIGHUP`
(`systemctl reload rawstor-mds@<uuid>`). New chunks may then be placed on
it; existing ones stay where they are. Client connections are kept. A
topology that doesn't parse, or drops an OST still holding chunks, is
refused: on reload the current one is kept and the reason logged
(`Topology reload from ... failed, keeping the current one: ...`), at
startup the MDS doesn't start.

### Packaging and systemd instances

`rawstor-mds` ships in its own `rawstor-mds` deb/rpm package (needs
`sqlite3`; skip building it with `--without-sqlite3`), along with the
`rawstor-mds@.service` systemd template and a commented topology example,
`/usr/share/doc/rawstor-mds/topology.conf`. One instance serves one
cluster, named after the cluster's id and configured by
`/etc/rawstor/mds/<uuid>.conf`. Installing the package starts nothing; an
instance without its config refuses to start.

The config is an environment file (`KEY=VALUE` lines):

| Key | Default | Description |
|-----|---------|-------------|
| `BIND_ADDR` | — (required) | `<ip>:<port>` to listen on, unique per host. |
| `TOPOLOGY_PATH` | `/etc/rawstor/mds/<uuid>.topology` | Topology file; must exist (may be empty) and be readable by `rawstor`. |
| `DB_PATH` | `/var/lib/rawstor/mds/<uuid>/mds.db` | Database; its directory must be writable by `rawstor`. |
| `QUEUE_SIZE` | `4096` | `--queue-size`. |
| `WORKERS` | `4` | `--workers`. |
| `RAWSTOR_MDS_OPTS_*`, `RAWSTOR_OPTS_*` | | Tuning knobs, see [Environment Variables](#environment-variables). |

The instance runs as the `rawstor` user under `ProtectSystem=strict`;
`/var/lib/rawstor/mds/<uuid>` (`StateDirectory=`) is created on start.
A database anywhere else needs a drop-in (`ReadWritePaths=`), as for
`rawstor-ost`.

Two clusters on one host:

```bash
for C in ${CLUSTER1} ${CLUSTER2}; do
    sudo cp my-${C}.topology /etc/rawstor/mds/${C}.topology
done
echo "BIND_ADDR=0.0.0.0:7776" | sudo tee /etc/rawstor/mds/${CLUSTER1}.conf
echo "BIND_ADDR=0.0.0.0:7786" | sudo tee /etc/rawstor/mds/${CLUSTER2}.conf
sudo systemctl enable --now rawstor-mds@${CLUSTER1} rawstor-mds@${CLUSTER2}

rawstor info mds://127.0.0.1:7776          # serving?
# edit /etc/rawstor/mds/${CLUSTER1}.topology, then
sudo systemctl reload rawstor-mds@${CLUSTER1}
journalctl -u rawstor-mds@${CLUSTER1} | grep Topology   # applied?
```

Removing an instance (`systemctl disable --now`, then deleting its config)
keeps its database; a package upgrade restarts the running instances and
removing the package stops them, leaving configs and databases in place.

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

### Buffer ring registration fails with EINVAL

```
io_uring_register_buf_ring failed: Invalid argument
```

Seen from `librawio`'s multishot recv path (`uring_buffer.cpp`), and from
anything that depends on it: `rawstor-ost` itself reads wire responses via
multishot recv with a registered provided buffer ring, so every `ost://`-backed
test (`OstIOTest`, `OstLifecycleTest`, `MirrorOstTest`, ...) and
`librawio`'s own `MultishotTest` fail with this same symptom when it's present.

Confirm it's this, not something this project is doing wrong, with a minimal
reproduction independent of librawstor entirely (`gcc repro.c -luring`):

```c
#include <liburing.h>
#include <sys/mman.h>
#include <string.h>

int main(void) {
    struct io_uring ring;
    io_uring_queue_init(16, &ring, 0);

    size_t size = 4096;
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    struct io_uring_buf_reg reg = {0};
    reg.ring_addr = (unsigned long long)(uintptr_t)buf;
    reg.ring_entries = 1; /* any power of 2 */
    reg.bgid = 1;

    return io_uring_register_buf_ring(&ring, &reg, 0); /* -EINVAL here */
}
```

If this fails identically regardless of `ring_entries`/size (including the
smallest possible registration), under `sudo`, with `ulimit -l` far above
what's being requested, and with `Seccomp: 0` in `/proc/self/status` -- it
isn't a resource limit, a privilege issue, or a code bug: `RLIMIT_MEMLOCK`,
`kernel.io_uring_disabled` (see above), and process privilege can all be ruled
out this way.

This combination -- Ubuntu's own `linux-image-*-generic` kernel,
`IORING_REGISTER_PBUF_RING` (provided buffer ring registration), `EINVAL` --
has been reported before: see
[axboe/liburing#1432](https://github.com/axboe/liburing/discussions/1432),
where the io_uring maintainer notes Ubuntu's kernel "is not part of the stable
series and does not receive updates." Canonical backports its own set of
`io_uring` security fixes onto an otherwise-frozen base version, independently
of upstream -- this exact code path has had several
([CVE-2024-0582](https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/),
CVE-2024-35880, CVE-2025-21836; see
[this write-up](https://u1f383.github.io/linux/2025/03/02/a-series-of-io_uring-pbuf-vulnerabilities.html))
-- a combination where behavior diverging from upstream's own is plausible.
There's no known `sysctl`/`ulimit` fix for it; running the affected tests
against a different kernel (a genuine upstream stable release, or a different
distribution's) is the only known way around it so far.
