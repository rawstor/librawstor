# Troubleshooting

## Operation not permitted
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

## Buffer ring registration fails with EINVAL

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
