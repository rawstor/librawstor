# Rawstor library and tools

[![Unit Test Status](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml/badge.svg?branch=main)](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml)

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

./vhost/rawstor-vhost \
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
| `RAWSTOR_OPTS_IO_ATTEMPTS` | `3` | Number of retry attempts for I/O operations that encounter recoverable errors. |
| `RAWSTOR_OPTS_SESSIONS` | `1` | Number of concurrent sessions that Rawstor client will open for each object. |
| `RAWSTOR_OPTS_SO_SNDTIMEO` | `5000` | Socket send timeout. Sets `SO_SNDTIMEO` for network sockets. |
| `RAWSTOR_OPTS_SO_RCVTIMEO` | `5000` | Socket receive timeout. Sets `SO_RCVTIMEO` for network sockets. |
| `RAWSTOR_OPTS_TCP_USER_TIMEOUT` | `5000` | TCP user timeout (Linux `TCP_USER_TIMEOUT`). Defines how long transmitted data may remain unacknowledged before the connection is closed. |
| `RAWSTOR_OPTS_LIST_LIMIT` | `10` | The maximum number of rows that can be returned in list functions. |

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

`rawstor-vhost [-h] -s SOCKET_PATH TARGET [--queue-size SIZE] [-v]`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-s, --socket-path PATH` | Location of the vhost-user Unix domain socket. |
| `TARGET` | Comma‑separated list of rawstor backend targets (see [Locations and Targets](https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth. Default: `256`. |
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
`VIRTIO_RING_F_INDIRECT_DESC` and `VIRTIO_RING_F_EVENT_IDX`, and services
read (`VIRTIO_BLK_T_IN`), write (`VIRTIO_BLK_T_OUT`) and identify
(`VIRTIO_BLK_T_GET_ID`) requests. `VIRTIO_BLK_T_FLUSH`, `_DISCARD` and
`_WRITE_ZEROES` are not implemented and are answered with
`VIRTIO_BLK_S_UNSUPP`. Although `VIRTIO_BLK_F_MQ` is negotiated (so a
front-end may query the queue count via `VHOST_USER_GET_QUEUE_NUM`), only a
single virtqueue is actually serviced per device.

### Notes

`rawstor-vhost` serves exactly one front-end connection per process
invocation: it accepts a connection on the socket, serves it until the
front-end disconnects (exiting cleanly), and then exits. A setup or
protocol error (e.g. a mismatched `num-queues`) is reported and also exits
the process, rather than silently waiting for another connection. Pair it
with `reconnect=1` on the QEMU chardev and an external supervisor (e.g.
`systemd` with `Restart=always`, or a wrapper loop) if the backend needs to
survive guest-side reconnects. Send `SIGINT`/`SIGTERM` to stop it.

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
