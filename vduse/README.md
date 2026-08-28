# rawstor-vduse

A [VDUSE](https://docs.kernel.org/userspace-api/vduse.html) virtio-blk
backend, structured like `vhost/` (its own `include/` + `src/` + `tests/`
split, RawIO-driven asynchronous I/O) and, like `vhost/`, implementing the
protocol natively -- no third-party protocol library (qemu's `libvduse`
included) is vendored or linked against. Only the kernel uAPI struct/ioctl
definitions themselves are vendored, trimmed the same way
`vhost/include/stdheaders/` vendors its own kernel headers.

See the top-level README's "rawstor-vduse" section for usage, packaging and
access requirements.
