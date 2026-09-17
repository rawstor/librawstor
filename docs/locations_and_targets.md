# Locations and Targets

## Overview

Rawstor addresses data through six related concepts, each with its own
URI form: **Location**, **Target**, **Object**, **Chunk**, **Slot**, and
**Snapshot**. A Location names a backend store; a Target names one
specific object within it; Object/Chunk/Slot are the layers a Target
decomposes into once opened; Snapshot is a bound version of any of them.
Only **Location** and **Target** are syntax a caller ever types by hand
(CLI arguments, `rawstor_target_*()`'s own `target` string) — Object,
Chunk and Slot are the client library's internal model of what a Target
opens into, described here so the two visible forms make sense in
context.

---

## Location

A **location** specifies the address of a backend data store (or a list
of backends). It is expressed as a comma-separated list of URIs. The URI
format follows the standard scheme `<scheme>://<endpoint>`.

Currently, four URI schemes are supported:

| Scheme | Description |
|--------|-------------|
| `ost`  | Backend server speaking the OST protocol (see [Protocol.md](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md)) |
| `file` | Local filesystem backend (a folder path) |
| `lvm`  | Local LVM thin pool backend |
| `zfs`  | Local ZFS pool backend |
| `mds`  | Metadata server addressing a whole chunked, possibly multi-copy volume rather than a single physical store (see [mds.md](mds.md)) |

### Single backend examples

- `ost://<host>:<port>` – an OST server at the given host and port.
- `file://<path_to_folder>` – a folder on the local filesystem.

### Multiple backends (comma‑separated)

When multiple URIs are listed, the client interprets the list according
to specific policies:

| Example | Behavior |
|---------|----------|
| `ost://host1:port1,ost://host2:port2` | **Mirroring** – both backends contain identical data. |
| `file:///data/folder,ost://host:port` | **Data locality** – the file backend serves as a local cache or fast access path, while the OST backend is the primary remote store. |

**Syntax rules:**
- Do not add spaces between URIs – use a single comma: `uri1,uri2`
- To include a literal comma within a URI, escape it with a backslash: `\,`
- Each URI must be a valid location (scheme + endpoint).
- All URIs in the list must be unique – duplicates are not allowed.

---

## Target

A **target** identifies a specific object a caller can open, read,
write, create, remove, or snapshot. For a single-URI target, the format
is `<scheme>://<endpoint>/<uuid>`. For multiple URIs (mirroring), the
UUID is appended to each one: `<scheme1>://<endpoint1>/<uuid>,<scheme2>://<endpoint2>/<uuid>,...`

Where:
- `<scheme>` and `<endpoint>` are the same as for location.
- `<uuid>` is the unique identifier of the object (rawstor uses UUID v7).

### Single backend target examples

- `ost://<host>:<port>/<uuid>` – an object stored on a single OST server.
- `file://<path_to_folder>/<uuid>` – an object stored as a file in a local folder.
- `mds://<host>:<port>/<uuid>` – a whole volume addressed through its MDS; always a single URI (no comma list — mirroring/locality here happen per chunk, inside the volume, not at this level). See [mds.md](mds.md).

### Multiple backend target (mirroring / locality)

The client uses the same policies as for locations (mirroring, locality, etc.).

Example: `ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00`

This target references the same object (UUID `019cbfad-a389-7d42-a0f6-c29993ac8c00`) on two different backends.

**Important:** All URIs in a target list must point to the same UUID. Mixing different UUIDs in one target is not allowed.

### Internal multi-chunk form (not for manual entry)

Opening a target (`rawstor_target_open()`) resolves it into an
**Object** made of one or more **Chunks** (see below). For a plain
target, this is always a single chunk — the target string above, in
full. `mds://` volumes need more than one: the client library builds,
internally, a single flat `,`-separated list of every chunk's own URIs,
one after another, with no second separator marking where one chunk's
own group ends and the next begins — `Target`'s own constructor sorts
them back into their chunk groups itself, by each URI's own internal
`:<offset>` suffix (a chunk's byte offset within the volume, `logical_
index * chunk_size` — URIs sharing one offset are mirrors of the same
chunk, distinct chunks always differ). This form only ever exists inside
the library (built by the MDS backend from the volume's chunk map) — it
is never part of the target syntax a caller types, appears in the CLI,
or is returned by any `rawstor_target_*()` call. It is documented here
only so the internal model below is unambiguous about where a
multi-chunk Object's own per-chunk URI lists come from.

---

## Object

The **Object** is the client-facing handle a target opens into
(`rawstor_docs/Architecture.md`: "Object = group of chunks") — what
`rawstor_target_open()` returns, and what every `rawstor_object_*()` I/O
call (`pread`/`pwrite`/`discard`/`write_zeroes`/`flush`/`close`) acts on.
It has no URI form of its own: it is *derived* from the target string
that opened it, routing each I/O request to the Chunk that logically
owns the touched byte range. A plain target's Object is always the
degenerate case of exactly one Chunk; an `mds://` volume's Object may
route across many.

## Chunk

A **Chunk** is one logical piece of an Object's data — for a plain
target, the whole object; for an `mds://` volume, one fixed-size slice of
it (docs/mds.md: with 1 GiB chunks, a 1 TiB volume has ≤ 1024 chunks). A
Chunk owns the mirror-consistency protocol (DIRTY/CLEAN/SYNCING,
epoch/sync_id, degrade/resync — docs/mirroring.md) across its own one or
more Slots. Its URI form is exactly a plain target's own: one URI per
mirror, comma-separated, all sharing the same UUID —
`ost://h1:p1/<uuid>,ost://h2:p2/<uuid>`. A single-chunk Object's one
Chunk *is* the target string that opened it; a multi-chunk `mds://`
volume's chunks are each one same-`:<offset>` group of the internal form
above.

## Slot

A **Slot** is one physical mirror arm of a Chunk: a single URI, backed by
one connection pool against one backend, responsible for retrying and
reconnecting on that one arm independently of its siblings. Its URI form
is a single, bare URI: `ost://h1:p1/<uuid>`. A Chunk with N mirrors has N
Slots; a plain, unmirrored target's Chunk has exactly one.

## Snapshot

A **snapshot** is a bound, read-only version of a target/chunk/slot,
identified by a version id (`snap_id`, never 0 — 0 always means "live").
Two independent mechanisms use it, at different layers:

- **mds:// volume-level**: `vol_snap_begin`/CoW-every-chunk/
  `vol_snap_commit` (docs/mds.md, "Snapshots (stage 2)") registers a new
  id against the whole volume, driven by `mds::Backend::
  snapshot_create_assign()`.
- **Per-slot native CoW**: a single backend's own thin-clone/snapshot
  primitive (zfs::Backend today), addressed directly by target/chunk-
  slot URI with the version appended as `@<snap_id>`:
  `ost://host:port/<uuid>@5` or, on a bare (non-mds://) target,
  `mds://host:port/<volume_id>@5`. This suffix is never part of a
  location and never carries a comma-separated list of its own — it
  binds whichever single URI it's attached to.

## Chunk offset (not for manual entry)

A chunk's own byte offset within its parent `mds://` volume
(`logical_index * chunk_size`) rides the same URI, as a `:<offset>`
suffix right after the UUID: `ost://host:port/<uuid>:1048576` (optionally
followed by `@<snap_id>`, e.g. `ost://host:port/<uuid>:1048576@5`). Like
the internal multi-chunk form above, this is built only by `mds::Backend`
from its own chunk map and never something a caller types — `Target`'s
own constructor reads it back out to reconstruct chunk grouping, and it's
also readable through `Target::offset()`/`rawstor_target_offset()`
directly (0 for a plain, non-`mds://` target).

---

## Summary table

| Concept | Format | Purpose | Example |
|---------|--------|---------|---------|
| **Location** | `<scheme>://<endpoint>` or `uri1,uri2,...` | Address of a backend data store (or a set of stores) | `ost://127.0.0.1:9090`<br>`file:///var/rawstor` |
| **Target** | `<scheme>://<endpoint>/<uuid>` or `uri1,uri2,...` | Address of a specific object a caller opens/creates/removes | `ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00`<br>`ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00` |
| **Object** | (none — derived from the target string that opened it) | The open handle `rawstor_object_*()` I/O acts on; routes to the owning Chunk | — |
| **Chunk** | Same as Target: `uri1,uri2,...` (one UUID per group) | One logical slice of an Object's data; owns mirror consistency | `ost://h1:p1/<uuid>,ost://h2:p2/<uuid>` |
| **Slot** | A single URI | One physical mirror arm of a Chunk; owns retries/reconnects | `ost://h1:p1/<uuid>` |
| **Snapshot** | `@<snap_id>` suffix on a target/chunk-slot URI, or a volume-level id assigned by the MDS | A bound, read-only version | `ost://host:port/<uuid>@5` |

---

## Notes

- When using the `file://` scheme, the path must be absolute. Relative paths are not allowed.
- The OST protocol details, including authentication, error handling, and streaming, are defined in the [protocol specification](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md).
- **On naming**: this document's "Location"/"Target" pair, and the
  Object/Chunk/Slot model above, could arguably be called a "topology" —
  but that word is already taken: [mds.md](mds.md) uses "topology" for a
  different, unrelated concept (the MDS's own static list of known OSTs,
  `TOPOLOGY_PATH`/`topology.conf`, scanned by `rawstor-mds --reconstruct`).
  Reusing it here for this document would make the two docs' shared
  vocabulary actively misleading, so this file keeps its current name.
