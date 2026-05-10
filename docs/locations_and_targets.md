# Locations and Targets

## Overview

Rawstor client library and OST backend use two core concepts to address and access data: **Location** and **Target**.

---

## Location

A **location** specifies the address of a backend data store (or a list of backends). It is expressed as a comma-separated list of URIs. The URI format follows the standard scheme `<scheme>://<endpoint>`.

Currently, two URI schemes are supported:

| Scheme | Description |
|--------|-------------|
| `ost`  | Backend server speaking the OST protocol (see [Protocol.md](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md)) |
| `file` | Local filesystem backend (a folder path) |

### Single backend examples

- `ost://<host>:<port>` – an OST server at the given host and port.
- `file://<path_to_folder>` – a folder on the local filesystem.

### Multiple backends (comma‑separated)

When multiple URIs are listed, the client interprets the list according to specific policies:

| Example | Behavior |
|---------|----------|
| `ost://host1:port1,ost://host2:port2` | **Mirroring** – both backends contain identical data. |
| `ost://host1:port1,file:///data/folder` | **Data locality** – the OST backend is the primary remote store, and the file backend serves as a local cache or fast access path. |

**Syntax rules:**
- Do not add spaces between URIs – use a single comma: `uri1,uri2`
- Each URI must be a valid location (scheme + endpoint).
- All URIs in the list must be unique – duplicates are not allowed.

---

## Target

A **target** identifies a specific data object within a location (or a set of locations). Its format is: <location>/<uuid>


Where:
- `<location>` is a location URI as defined above.
- `<uuid>` is the unique identifier of the object (rawstor uses UUID v7).

### Single backend target examples

- `ost://<host>:<port>/<uuid>` – an object stored on a single OST server.
- `file://<path_to_folder>/<uuid>` – an object stored as a file in a local folder.

### Multiple backend target (mirroring / locality)

A target may also contain a comma‑separated list of location‑UUID pairs. **When multiple locations are given, the UUID must be identical across all entries.** The client uses the same policies as for locations (mirroring, locality, etc.).

Example: `ost://host1:port1/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00`

This target references the same object (UUID `019cbfad-a389-7d42-a0f6-c29993ac8c00`) on two different backends.

**Important:** All URIs in a target list must point to the same UUID. Mixing different UUIDs in one target is not allowed.

---

## Summary table

| Concept | Format | Purpose | Example |
|---------|--------|---------|---------|
| **Location** | `scheme://endpoint` or `uri1,uri2,…` | Address of a backend data store (or a set of stores) | `ost://127.0.0.1:9090`<br>`file:///var/rawstor` |
| **Target** | `<location>/<uuid>` or `<loc1>/<uuid>,<loc2>/<uuid>,…` | Address of a specific data object | `ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00`<br>`ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00,file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00` |

---

## Notes

- When using the `file://` scheme, the path must be absolute. Relative paths are not allowed.
- The OST protocol details, including authentication, error handling, and streaming, are defined in the [protocol specification](https://github.com/rawstor/rawstor_docs/blob/main/Protocol.md).
