# Locations and Targets

## Status

Legend: ✅ implemented · 🟡 partial · ❌ not implemented yet. Checked against
the `releases/v0.2` code on 2026-10-04.

| Feature | Status | Where |
|---|---|---|
| `ost://`, `file://`, `lvm://`, `zfs://` schemes | ✅ | `src/backend.cpp`, `src/*_backend.cpp` |
| Comma-separated location/target lists, duplicate URIs rejected | ✅ | `src/location.cpp`, `src/target.cpp` |
| All URIs of a target share one UUID | ✅ | `src/target.cpp` (`validate_same_uuid()`) |
| `\,` escaping inside a URI | ✅ | `librawstd/src/uri.cpp` |
| Mirroring (`ost://a,ost://b`) | 🟡 | writes go to every copy; see *Multiple backends* for the limits (`src/chunk.cpp`) |
| Data locality (`file://` on the hypervisor + `ost://`) | 🟡 | works as a mirror with the local copy listed first; no cache / primary-store asymmetry |

## Overview

Rawstor client library and OST backend use two core concepts to address and access data: **Location** and **Target**.

---

## Location

A **location** specifies the address of a backend data store (or a list of backends). It is expressed as a comma-separated list of URIs. The URI format follows the standard scheme `<scheme>://<endpoint>`.

Currently, four URI schemes are supported:

| Scheme | Description |
|--------|-------------|
| `ost`  | Backend server speaking the OST protocol (see [Protocol.md](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md)) |
| `file` | Local filesystem backend (a folder path) |
| `lvm`  | Local LVM volume group backend (`lvm://<vg>`) |
| `zfs`  | Local ZFS pool backend (`zfs://<pool>[/<dataset>]`) |

### Single backend examples

- `ost://<host>:<port>` – an OST server at the given host and port.
- `file://<path_to_folder>` – a folder on the local filesystem.

### Multiple backends (comma‑separated)

When multiple URIs are listed, the client interprets the list according to specific policies:

| Example | Behavior |
|---------|----------|
| `ost://host1:port1,ost://host2:port2` | **Mirroring** – both backends contain identical data. |
| `file:///data/folder,ost://host:port` | **Data locality** – the file backend serves as a local cache or fast access path, while the OST backend is the primary remote store. |

In this release both policies are the same simple mirror:

- Reads are always served by the first URI in the list, so list the local
  `file://` copy first for data locality. A failed read is not retried on
  another copy.
- A write, discard or flush goes to every copy and is acknowledged only once
  all of them complete, so write latency is the slowest copy's. If any copy
  fails, the operation fails with `-EIO`; the object does not continue on
  the remaining copies.
- Opening needs every copy reachable.
- There is no per-copy consistency metadata, quorum or resync: copies that
  diverged (e.g. after a failed write) are not detected or repaired.
- The local copy is a full copy of the object, not a cache with eviction.

**Syntax rules:**
- Do not add spaces between URIs – use a single comma: `uri1,uri2`
- To include a literal comma within a URI, escape it with a backslash: `\,`
- Each URI must be a valid location (scheme + endpoint).
- All URIs in the list must be unique – duplicates are not allowed.

---

## Target

A **target** identifies a specific data object. For a single target, the format is `<scheme>://<endpoint>/<uuid>`. For multiple targets, the UUID must be appended to each URI: `<scheme1>://<endpoint1>/<uuid>,<scheme2>://<endpoint2>/<uuid>,...`

Where:
- `<scheme>` and `<endpoint>` are the same as for location.
- `<uuid>` is the unique identifier of the object (rawstor uses UUID v7).

### Single backend target examples

- `ost://<host>:<port>/<uuid>` – an object stored on a single OST server.
- `file://<path_to_folder>/<uuid>` – an object stored as a file in a local folder.

### Multiple backend target (mirroring / locality)

The client uses the same policies as for locations (mirroring, locality, etc.).

Example: `ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00`

This target references the same object (UUID `019cbfad-a389-7d42-a0f6-c29993ac8c00`) on two different backends.

**Important:** All URIs in a target list must point to the same UUID. Mixing different UUIDs in one target is not allowed.

---

## Summary table

| Concept | Format | Purpose | Example |
|---------|--------|---------|---------|
| **Location** | `<scheme>://<endpoint>` or `uri1,uri2,...` | Address of a backend data store (or a set of stores) | `ost://127.0.0.1:9090`<br>`file:///var/rawstor` |
| **Target** | `<scheme>://<endpoint>/<uuid>` or `uri1,uri2,...` | Address of a specific data object | `ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00`<br>`ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00` |

---

## Notes

- When using the `file://` scheme, the path must be absolute. Relative paths are not allowed.
- The OST protocol details, including authentication, error handling, and streaming, are defined in the [protocol specification](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md).
