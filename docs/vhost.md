# rawstor-vhost – vhost-user-blk Backend

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

## Usage

`rawstor-vhost [-h] -s SOCKET_PATH TARGET [--queue-size SIZE] [--write-cache on|off] [--readonly] [--force] [-v]`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-s, --socket-path PATH` | Location of the vhost-user Unix domain socket. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Concepts](concepts.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth of each virtqueue's own queue. Default: `4096`. |
| `--write-cache on\|off` | Advertise a writeback (`on`) or write-through (`off`, default) cache to the guest; write-through makes every write durable on completion, writeback relies on the guest issuing an explicit flush. |
| `--readonly` | Export the object read-only: advertises `VIRTIO_BLK_F_RO` to the guest and opens `TARGET` with `RAWSTOR_READONLY` (writes fail; the mirror quorum is still required). Required to export a version target. |
| `--force` | With `--readonly`, also open `TARGET` with `RAWSTOR_FORCE`: no mirror write quorum needed. Has no effect without `--readonly`. |
| `-v, --version` | Print version and exit. |

## Example

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

## Supported virtio-blk features

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

## Notes

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
off. After growing the object (`rawstor object resize`), send `SIGHUP`: the
backend re-reads the size, reopens its connections to the target so I/O
reaches the new space, and sends `VHOST_USER_BACKEND_CONFIG_CHANGE_MSG` so
the front-end re-reads the config and tells the guest (QEMU updates the
disk capacity and raises a config interrupt). A size that did not grow is
ignored. It also negotiates `VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD`: every
request is logged in shared memory QEMU keeps across backend restarts, so
after a crash the restarted backend resubmits whatever was left in
flight, in its original order.

`rawstor-vhost` supports QEMU live migration of the VM. It negotiates
`VHOST_USER_PROTOCOL_F_LOG_SHMFD` and `VHOST_F_LOG_ALL`: while a migration
is copying memory, QEMU shares a dirty page bitmap and the backend marks
every guest page it writes (the buffers of each completed request and the
used ring) before the completion reaches the guest. On the source,
`GET_VRING_BASE` stops each ring and is answered only once its in-flight
requests are done. The destination's `rawstor-vhost` opens the same object
ahead of time but writes only after that hand-over; both processes
holding the object open meanwhile is what [multi-attach](multiattach.md)
stage 2 covers for mirrored objects.
`rawstor-vhost-qemu` gets this from libvhost-user; `rawstor-vduse` has no
dirty page logging.

## Packaging and QEMU access

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
