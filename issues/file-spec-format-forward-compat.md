# file:// backend: no forward-compat guard for the v1 .spec format

## Where

`src/file_session.cpp`, `read_meta_fd()` (around line 82-111):

```cpp
RawstorObjectMeta read_meta_fd(int fd) {
    OnDiskMeta disk{};
    ssize_t rval = ::pread(fd, &disk, sizeof(disk), 0);
    ...
    if (rval == sizeof(RawstorObjectSpec)) {
        /* Legacy version 0: size only. */
        ...
    }

    if (rval != sizeof(disk) || disk.magic != RAWSTOR_MAGIC) {
        rawstd_error("Malformed object spec\n");
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    ...
}
```

This handles the **old → new** direction (a pre-mirroring 8-byte
`RawstorObjectSpec` record is recognized by its size and migrated to the
128-byte versioned `OnDiskMeta` format on the next `set_state()`), and
already checks `disk.version != META_FORMAT_VERSION` for a version that's
*newer than what this build knows* — but only after successfully reading a
full 128-byte record with the correct magic.

## Problem

The check assumes any reader of a `.spec` file is at least new enough to
understand the 128-byte layout. It does **not** cover the reverse direction:
an **old** librawstor build (still on the pre-mirroring naive 8-byte
`pread(fd, &spec, sizeof(RawstorObjectSpec), 0)` read, i.e. anything before
`add/mirror-metadata`) reading a `.spec` file that a **new** build has since
migrated to the 128-byte v1 format. The old code has no magic/version check
at all — it just reads the first 8 bytes of the 128-byte record and
interprets them as `RawstorObjectSpec.size`. The first 8 bytes of
`OnDiskMeta` are `{ uint32_t magic; uint32_t version; }` (`RAWSTOR_MAGIC` in
the low 32 bits, `1` in the high 32 bits on a little-endian host), so the old
build would compute a garbage, enormous size (`magic | (version << 32)`)
instead of erroring out.

This only matters for a **mixed-version deployment sharing the same file://
directory** — e.g. a rolling upgrade where an old and a new librawstor binary
both touch the same object storage directory, or an operator running old and
new `rawstor-ost`/`rawstor-cli` binaries side by side against the same path.
Not a risk for a single-version deployment.

## Suggested fix

Two independent options, not mutually exclusive:

- **Structural**: make the magic number itself distinguish "this is a
  versioned record" from "this is raw size data" in a way that's meaningful
  even to old code doing a naive 8-byte read — e.g. choose `RAWSTOR_MAGIC`'s
  bytes so that, reinterpreted as a `uint64_t` size by old code, the result
  is implausibly large in a way old code could sanity-check (fragile, and
  already shipped, so changing it now is itself a migration hazard).
- **Operational**: document the constraint explicitly (no mixed-version
  `file://` deployments sharing a directory) since that's the actual
  practical mitigation available without a wire/format change at this point.

## Note

Surfaced during AI review of the `add/mirror-metadata` branch. Not yet
fixed; low priority relative to the other tracked issues since it only
bites a specific mixed-version operational scenario.
