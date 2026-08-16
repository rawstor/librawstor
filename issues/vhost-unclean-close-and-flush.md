# vhost: unclean close, guest FLUSH not proxied

## Where

- `vhost/device.cpp:668` — `rawstor_object_close(_object)`.
- `vhost/device.cpp:467-472` — `VIRTIO_BLK_T_FLUSH` falls into the same
  `case` as `DISCARD`/`WRITE_ZEROES`/`default` and is answered with
  `VIRTIO_BLK_S_UNSUPP`.
- `vhost/device.cpp:583` — `VIRTIO_BLK_F_FLUSH` is commented out of the
  advertised feature bits, so guests never even attempt a flush today.

## Problem

Two related gaps, both present since before the mirroring work:

1. **Unclean close.** `rawstor_object_close()` is a bare `delete` — it does
   not flush pending writes or mark mirror copies `CLEAN` before releasing
   the handle (see `rawstor_object_close_async`, added on
   `add/mirror-metadata`, which does both). Every real close path in vhost
   goes through the unclean variant, so a mirrored object backing a VM disk
   never reaches `CLEAN` on a normal VM shutdown — the "`CLEAN` ⇒ trusted"
   guarantee in `docs/mirroring.md` is unreachable in practice for vhost
   guests.
2. **No flush passthrough.** Because `VIRTIO_BLK_F_FLUSH` isn't advertised,
   a guest OS/filesystem can never ask the device to flush at all — cache
   flush barriers (fsync, journal commits, etc. inside the guest) are
   silently no-ops from the guest's point of view (the request is rejected
   with `UNSUPP` rather than acknowledged after doing nothing, so a
   flush-aware guest filesystem should at least notice — but no flush ever
   happens either way).

## Suggested fix

- Advertise `VIRTIO_BLK_F_FLUSH` and handle `VIRTIO_BLK_T_FLUSH` by calling
  `rawstor_object_flush()` and pushing `VIRTIO_BLK_S_OK`/`VIRTIO_BLK_S_IOERR`
  based on the result, instead of grouping it with the genuinely unsupported
  `DISCARD`/`WRITE_ZEROES` cases.
- Switch `vhost/device.cpp:668` to `rawstor_object_close_async()` (already
  exists; used nowhere yet) so a clean VM shutdown durably marks the
  mirror copies `CLEAN`.

## Note

This is tracked as a known gap, not yet fixed — flagged during the
`add/mirror-metadata` review as pending follow-up work.
