# rawstor-vduse

A [VDUSE](https://docs.kernel.org/userspace-api/vduse.html) virtio-blk
backend, structured like `vhost/` (its own `include/` + `src/` + `tests/`
split, RawIO-driven asynchronous I/O) but built on vendored qemu `libvduse`
(`3rdparty/qemu/libvduse/`, never patched -- see `AGENTS.md`) for the VDUSE
kernel control-plane protocol itself, the way `vhost-qemu/` is built on
vendored `libvhost-user`.

See the top-level README's "rawstor-vduse" section for usage, packaging and
access requirements.
