# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added

- [Mirroring design](docs/mirroring.md): failure model, quorum rules and
  online resync for N-way mirrors.
- Per-copy object metadata (state/epoch/sync_id/history) in a versioned
  `.spec` format; legacy size-only records are read and migrated
  transparently.
- SPEC, SET_STATE and FLUSH commands in the OST protocol; unknown commands
  are now answered with `-ENOSYS` before the connection is closed.
- `rawstor_object_meta`, `rawstor_object_set_state` (sync and async) and
  `rawstor_object_flush` public API.
- Durable metadata updates: object create and state changes are fsynced by
  the file backend.
- Mirror quorum rules: opening a mirrored object requires a strict
  majority of reachable members (`-ENOTCONN` otherwise); stale and
  interrupted-resync copies are excluded by sync-id comparison; disjoint
  write histories are refused (`-ENOTRECOVERABLE`).
- Degrade & continue: a mirrored write that fails on some members is
  acknowledged once the exclusion is durably recorded on the survivors;
  with three or more members writes freeze below the majority.
- Read failover across mirror members with read-repair of corrupted regions.
- `rawstor_object_close_async`: clean close that flushes and durably marks
  the copies CLEAN; `rawstor_object_close` stays an unclean close.
- Online resync: a stale mirror member is brought back while the object keeps
  serving I/O — client writes are duplicated onto the joining member while a
  sweeper copies the rest chunk by chunk; on completion the member adopts the
  current sync set durably and resumes serving reads.
- Reconnect probe: an open mirrored object periodically retries its
  unreachable members (`mirror_probe_interval` option /
  `RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL`, default 5000 ms) and resyncs them
  on reconnection, restoring the write quorum automatically.

### Fixed

- `rawstor_object_spec` over `ost://` returns the real object size instead
  of a hardcoded stub.
- OST error responses no longer desync the receive stream: a server-side
  error carries no payload, but the response frame itself was previously
  discarded as if the connection had died, corrupting the framing of every
  request that followed. The real errno is now also propagated instead of
  being masked as `EPROTO`.
- `rawstor_object_spec` over `ost://` falls back to the emulated metadata
  for OST servers predating the SPEC command whether they close the
  connection outright or reply with an ordinary error frame for the
  unknown command, matching real legacy server behavior.

## [0.2.0] - 2026-06-03

### Added

- Multishot IO operations.
- Units for command line arguments.
- [Location and target](docs/locations_and_targets.md) conception.
- OST backend implementation.
- Multiqueue support.
- Add allocate and release methods to the OST protocol.
- Python bindings.

## [0.1.2] - 2026-06-02

## [0.1.1] - 2026-05-26

## [0.1.0] - 2025-12-29

## [0.0.2] - 2026-05-26

## [0.0.1] - 2025-12-29

## [0.0.0] - 2025-10-26
