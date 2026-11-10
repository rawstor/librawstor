# rawstor-vduse – VDUSE virtio-blk Backend

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

## Usage

`rawstor-vduse [-h] TARGET [--queue-size SIZE] [--num-queues N] [--write-cache on|off] [--readonly] [--force] [-v]`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Concepts](concepts.md)). Creates `/dev/vduse/UUID`, where `UUID` is the target object's own UUID -- there is no separate name to pick, since the UUID already uniquely and stably identifies it. |
| `--queue-size SIZE` | Virtqueue size, a power of two, of each virtqueue's own queue. Default: `256`, max `1024`. |
| `--num-queues N` | Number of virtqueues advertised to the guest. Each one the driver actually enables is serviced by its own thread and its own connection to `TARGET`, started at that point (Linux's `virtio_blk` enables up to its CPU count). Default: the host's number of CPUs. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest. |
| `--readonly` | Export the object read-only: advertises `VIRTIO_BLK_F_RO` to the guest and opens `TARGET` with `RAWSTOR_READONLY` (writes fail; the mirror quorum is still required). Required to export a version target. |
| `--force` | With `--readonly`, also open `TARGET` with `RAWSTOR_FORCE`: no mirror write quorum needed. Has no effect without `--readonly`. |
| `-v, --version` | Print version and exit. |

## Example

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

## Supported virtio-blk features

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

## Notes

`rawstor-vduse` creates one VDUSE device per process invocation and keeps
running until the process is stopped (`SIGINT`/`SIGTERM`) or the VDUSE
device itself is destroyed out from under it -- unlike `rawstor-vhost`,
there is no per-connection front-end to disconnect from, since the kernel
is always "connected". Attaching the created device to the vDPA bus (`vdpa
dev add name UUID mgmtdev vduse`) and, if applicable, driving it from a
VMM, are separate, external steps.

After growing the object (`rawstor resize`), send `SIGHUP`: the process
re-reads the size, reopens its connections to the target so I/O reaches
the new space, updates the device's config space and raises a config
interrupt, so the guest sees the new capacity. A size that did not grow is
ignored.

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

## Packaging and access

`rawstor-vduse` ships in its own `rawstor-vduse` deb/rpm package (separate
from `librawstor`), along with the `rawstor-vduse@.service` systemd
template unit and a udev rule granting the `rawstor` system user/group
(shared with `rawstor-ost`/`rawstor-vhost`) access to `/dev/vduse/control`
and the device nodes it creates under `/dev/vduse/`.

Creating a VDUSE device requires the `vduse` kernel module (`modprobe
vduse`), and attaching it to the vDPA bus requires the `vdpa` tool
(`iproute2`) and `CAP_NET_ADMIN` -- neither is something `rawstor-vduse`
itself does; both are external, one-time-per-device administrative steps.
