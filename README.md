[![unittest](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml/badge.svg)](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml)

# Rawstor client library

## TL;DR
```
./autogen.sh
./configure --prefix=${HOME}/local
make
make install
```

## Configure

### Disable liburing

```
./configure --without-liburing
```

This will replace liburing with poll.

### Disable OST

```
./configure --disable-ost
```

This will disable OST integration and replace it with local file backend.

## Testing

```
make test
```

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
