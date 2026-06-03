# Rawstor library and tools

[![Unit Test Status](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml/badge.svg?branch=main)](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml)

## TL;DR
```
PREFIX=${HOME}/local

./autogen.sh
./configure --prefix=${PREFIX}
make -j$(nproc)
make install

OST_ADDR=192.168.0.1:8080

##
# OST Server
#
OST_DATADIR=/var/rawstor
OBJECT_SIZE=1g

mkdir -p ${OST_DATADIR}

OBJECT_ID=$(rawstor-cli create --size=${OBJECT_SIZE} --location=file://${OST_DATADIR})
echo OBJECT_ID=${OBJECT_ID}

rawstor-ost \
    --bind ${OST_ADDR} \
    --location file://${OST_DATADIR}

##
# Client
#
OBJECT_ID=...  # See above in OST Server section
VHOST_RUNDIR=${PREFIX}/var/run/rawstor

mkdir -p ${VHOST_RUNDIR}

./vhost/rawstor-vhost \
    --socket-path=${VHOST_RUNDIR}/rawstor1.sock \
    --target=ost://${OST_ADDR}/${OBJECT_ID}

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

> **Note:** All timeout values are expressed in milliseconds unless stated otherwise.

## rawstor-ost – OST Protocol Server

`rawstor-ost` implements the **OST protocol** (see [Protocol.md](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md)), handling network connections and providing access to data stored in **locations** (as defined in the [Locations and Targets](https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md) documentation).

- `file://` scheme → serves data directly from the local filesystem.
- `ost://` scheme → acts as a proxy to an underlying OST backend.
- Comma‑separated list → supports mirroring or data locality.

### Usage

`rawstor-ost [-h] -l LOCATION -b ADDR`

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-l, --location LOCATION` | Comma‑separated list of backend locations (e.g., `file:///path`, `ost://host:port`). |
| `-b, --bind ADDR` | Bind address in `<ip>:<port>` format (e.g., `127.0.0.1:8080`). |

### Examples

Serve local directory:
```bash
rawstor-ost -l file:///var/rawstor/data -b 0.0.0.0:8080
```

Proxy to remote OST:
```bash
rawstor-ost -l ost://192.168.1.100:8080 -b 0.0.0.0:8080
```

Data locality (local cache + proxy):
```bash
rawstor-ost -l file:///var/rawstor/data,ost://remote:8080 -b 0.0.0.0:8080
```

Mirroring between two OST backends:
```bash
rawstor-ost -l ost://left:8080,ost://right:8080 -b 0.0.0.0:8080
```

## rawstor-vhost

rawstor-vhost is a userspace VirtIO block device backend that implements the vhost-user protocol. It allows virtual machines to access block storage via shared memory, bypassing the host kernel for improved performance.

```
PREFIX=${HOME}/local
OST_ADDR=192.168.0.1:8080
OBJECT_ID=...
VHOST_RUNDIR=${PREFIX}/var/run/rawstor

rawstor-vhost \
    --socket-path=${VHOST_RUNDIR}/rawstor1.sock \
    --target=ost://${OST_ADDR}/${OBJECT_ID}

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
