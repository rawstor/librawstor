# Mirroring: Failure Model and Recovery

## Overview

A comma-separated target list (see [Locations and Targets](locations_and_targets.md)) makes the client keep N identical copies of an object on different backends. This document defines the failure model for N-way mirroring: what can fail, how the client reacts, and how byte-for-byte identity of the copies is restored afterwards. Erasure coding is out of scope.

Status: stages 1-3 are implemented (per-copy metadata, quorum open, degrade & continue, read failover/repair, clean close, online resync with automatic rejoin through a periodic reconnect probe) for all backends, including `lvm://`/`zfs://` (native ZFS user properties / LVM tags — see below). Not yet implemented: a persistent write-intent bitmap (a crashed resync restarts from scratch and an unclean shutdown costs a full resync), stored checksums/scrub, the MDS witness.

Error codes: open without quorum fails with `-ENOTCONN`; split brain (or no trusted member) fails with `-ENOTRECOVERABLE`; writes below the write quorum or with no member left fail with `-EIO`.

---

## Model and assumptions

- **Single writer per object.** An object is a virtual disk used by one client at a time (e.g. one VM via `rawstor-vhost` or the QEMU driver). Enforcing exclusivity (leases / exclusive open) is out of scope and is assumed.
- **Client-side replication.** The client fans out writes to all mirrors; OSTs do not know about each other and never talk to each other.
- **Identity** means: after recovery completes, all IN-SYNC copies are byte-for-byte equal. Writes that were never acknowledged to the caller may land on any subset of copies or none (RAID1 write-hole semantics — the application must not rely on them).
- **Write acknowledgement** to the caller requires completion on **all IN-SYNC mirrors** (latency = slowest mirror).

---

## Per-copy metadata

Each backend stores, next to the object data, a metadata record (an extension of the current `.spec`, which today holds only `size`). The on-disk format is versioned.

| Field | Type | Meaning |
|-------|------|---------|
| `size` | uint64 | Logical object size (as today) |
| `state` | enum | `CLEAN` \| `DIRTY` \| `SYNCING` |
| `epoch` | uint64 | Monotonic counter; bumped on every change of mirror-set health/membership |
| `sync_id` | uint64 | Random id of the current sync set; regenerated on degrade and on resync completion |
| `sync_id_history[4]` | uint64[] | Previous `sync_id`s (ancestry), DRBD-generation-UUID style |

`STALE` is not stored — it is derived by comparing copies.

### Comparison rules (at open)

| Observation | Verdict |
|-------------|---------|
| Same `sync_id`, all `CLEAN` | Copies are identical |
| `sync_id` of copy A appears in history of copy B | A is an ancestor → A is stale, resync A ← B |
| Different `sync_id`s, neither is an ancestor of the other | **Split brain** — automatic resync forbidden. Unreachable through automatic paths thanks to quorum rules (below); kept as defense in depth |
| `state == SYNCING` | Copy is untrusted (interrupted resync) — always stale |

### Durability rule

Metadata transitions (marking `DIRTY`, epoch/`sync_id` bump, resync completion) are performed on the backend **with fsync**, and **before** any dependent operation is acknowledged to the caller. These transitions are rare, so this is cheap. Data writes are *not* fsynced per-request; the resulting exposure is covered by rule F6 below.

---

## Quorum: excluding split brain by construction

Key invariant: **every acknowledged write exists on a set of copies that intersects any future auto-start set.** Therefore the newest `sync_id` is always visible at auto-start, and two disjoint write histories cannot be created through automatic paths.

- **Auto-start (open) requires strictly more than N/2 reachable mirrors** (N=2 → both). Within the reachable majority, the copy with the newest `sync_id` is authoritative (majority intersection guarantees it is present); stale copies get an online resync.
- **Below quorum: manual approval only** (force-open via CLI/opts). There is deliberately no "clean exception": `CLEAN` only means "I was closed correctly" — a copy cannot know locally that it did not miss anything while offline. Alternating offline periods of `CLEAN` copies would produce split brain.
- **Runtime (object already open):**
  - N ≥ 3: degrade & continue while more than N/2 mirrors survive; at ≤ N/2 survivors **writes freeze** (policy: error to the caller or block until quorum returns). Otherwise "wrote on minority {A}, later auto-started on majority {B,C}" would orphan acknowledged data.
  - N = 2: **continuing on a single survivor is allowed.** This is safe because auto-start requires both mirrors, and the abandoned peer remains `DIRTY`/ancestor and can never auto-start alone.
- **`sync_id_history` stays as defense in depth**: it catches consequences of a wrong manual force-open, an OST restored from backup, or bugs.
- **Roadmap — MDS as witness.** A future MDS participates in quorum as a metadata-only member (stores `sync_id`/`epoch`, no data). This restores auto-start for 2 data mirrors with one OST down (2 of 3 votes). Not part of v1, but quorum rules and the metadata format are designed so a witness member fits without schema changes (quorum counts all members, including metadata-only ones).

---

## Write lifecycle (all mirrors healthy)

1. **Open with write intent:** read metadata of all copies, verify identity, mark all copies `DIRTY` (fsync) before the first write is acknowledged.
2. **Write:** fan out to all IN-SYNC mirrors, acknowledge when all complete.
3. **Clean close:** flush data, set all copies `CLEAN` with the same `epoch`/`sync_id` (fsync).

---

## Failure cases

| # | Case | Detection | Reaction | Identity recovery |
|---|------|-----------|----------|-------------------|
| F1 | Write failure on one mirror M (network / EIO / timeout, per-connection retries exhausted) | error from the connection layer | If survivors > N/2 (or N=2 with 1 survivor): **suspend acks** → on survivors: `epoch`+1, new `sync_id`, old one pushed to history, fsync → mark M STALE in memory, exclude from I/O → resume acks. If survivors ≤ N/2 with N ≥ 3 — **freeze writes** (see quorum). Log + degradation event | Online resync when M returns (F7) |
| F2 | Read failure / transport hash mismatch on a mirror | error / EPROTO in the read path | Retry the read from another IN-SYNC mirror, return the data. **Read-repair**: rewrite the region on the failing mirror; if the repair write fails → degrade as in F1 | Pointwise via read-repair; on degradation — F7 |
| F3 | All mirrors failed | all connections dead | `EIO` to the caller, object unavailable. Periodic reconnect attempts | — (no copy available) |
| F4 | OST unreachable at open | connect failure | Reachable > N/2 → degraded open on the majority (it is guaranteed to contain the newest `sync_id`); on survivors `epoch`+1 / new `sync_id` **before the first write ack**. Reachable ≤ N/2 (N=2 with one down falls here) → **auto-start refused**, manual force-open only | F7 when it returns |
| F5 | Client crash with writes in flight | at next open: all copies `DIRTY` with the same `sync_id` | All copies are "valid" (they diverge only in unacknowledged regions). Deterministic winner: the first copy in the target list | v1: full online resync of the losers from the winner (expensive — the main argument for a persistent bitmap in v2). I/O is served from the winner immediately |
| F6 | OST crash/restart → acknowledged writes lost from page cache (data is not fsynced) | **not detectable from metadata** (the copy looks up to date) | **Conservative rule: any session loss to a mirror while the object is open `DIRTY` ⇒ that mirror is STALE (run the F1 procedure), even if it reconnects immediately.** We cannot know what it lost, so we do not trust it | Full resync (F7) overwrites whatever was lost |
| F7 | A stale mirror returns (rejoin) | reconnect probe + `sync_id`/`epoch` comparison: ancestor → stale | Mark the copy `SYNCING` (fsync), start an **online resync** (algorithm below) without stopping client I/O | On completion: copy metadata = source's `sync_id`/`epoch`, state `DIRTY` (object still open), fsync → mirror is IN-SYNC, reads allowed |
| F8 | Client/OST crash during resync | the copy is left `SYNCING` / with an old `sync_id` | Copy is untrusted | Resync from scratch (v1; resumable with the persistent bitmap in v2) |
| F9 | Split brain (disjoint write histories) | different `sync_id`s, neither in the other's history | **Excluded in automatic paths by the quorum rules.** Can only arise from a wrong manual force-open, an OST restored from backup, or a bug → then: open refused with a clear error, no automatic winner | Operator: `rawstor-cli resolve --winner=<uri>` → winner gets a new `sync_id`, the loser gets a full resync |
| F10 | Object missing on one OST (disk lost, OST reprovisioned) | ENOENT when opening the copy | Treat as stale: create the object (ALLOCATE) | Full online resync (F7) |
| F11 | Copy size mismatch (mixed file/blkdev backends round up to extent/volblocksize — see `src/blk_backend.hpp`) | spec comparison at open | The logical object size lives in metadata and is the same everywhere; physical ≥ logical is fine. Physical < logical → the copy is invalid (treat as F10) | — |
| F12 | Silent on-disk corruption (bit rot) | the transport hash does **not** catch it (the server hashes already-rotten data). `zfs://` catches it by itself; `file://` has nothing | v1: documented limitation; a scrub tool (chunk-wise comparison of copies) detects divergence under `CLEAN` metadata but cannot tell which copy is right | v1: operator decision. Long term (v3): stored per-chunk checksums |

---

## Online resync algorithm (client-driven, in-memory bitmap)

Requirements: no downtime, and regions already rewritten by the client onto all mirrors must not be copied again.

1. A bitmap lives in client memory; chunk size ~1 MiB (a 1 TiB object → 128 KiB of bitmap). Initially all bits are set = "needs copy" (v1 is always a full resync).
2. Client I/O continues throughout: reads are served **only from IN-SYNC mirrors**; **writes go both to IN-SYNC mirrors and to the SYNCING copy**. A write that fully covers a chunk clears its bit (that region is already identical). A partially covered chunk keeps its bit.
3. A sweeper walks the bitmap: for each set bit it reads the chunk from a source mirror, writes it to the SYNCING copy, clears the bit. Rate limiting (option) protects foreground I/O.
4. **Ordering hazard, sweeper × client write to the same chunk:** a per-chunk lock in client memory (single writer, cheap) — a client write to a chunk currently being copied waits for the chunk copy to finish (or vice versa). Otherwise the sweeper could overwrite a fresh client write with stale source data.
5. Bitmap empty → drain in-flight I/O → the SYNCING copy's metadata is set to the source's `sync_id`/`epoch` (fsync) → the mirror is IN-SYNC.

If the client or the target OST crashes mid-resync, the copy remains `SYNCING` and the resync restarts from scratch (F8). A persistent write-intent bitmap (v2) makes it resumable and shrinks the F5 full resync to recently-touched regions.

---

## Protocol and code changes

- **`include/rawstor/protocol.h`** — new opcodes:
  - `SPEC` — read metadata (size + state/epoch/sync_id/history); replaces the hardcoded stub in `rawstor::ost::Session::spec`;
  - `SET_STATE` — write metadata (fsynced on the server);
  - `FLUSH` — fdatasync of object data; needed for clean close and so that `rawstor-vhost`/QEMU can forward guest flushes.
  - An old server receiving an unknown opcode must answer `-ENOSYS`. There is no wire version field — acceptable before 1.0.
- **`src/file_backend.cpp`** — versioned `.spec` format; fsync of metadata.
- **`src/lvm_backend.cpp`/`src/zfs_backend.cpp`** — a raw block device has no `.spec` file and a reserved header/footer region is incompatible with objects already created (data occupies the device from byte 0). Metadata instead uses each backend's own native, transactional storage: a ZFS user property (`rawstor:meta`, set/read via `zfs set`/`zfs get`) or an LVM tag (`rawstor.meta=...`, via `lvchange --addtag`/`--deltag` and `lvs -o lv_tags`), encoded as a compact colon-separated hex string (`src/blkdev_meta.{hpp,cpp}`). Both mechanisms share the device/dataset's own failure domain and are set in the same command as creation, so there is never a window where the volume exists without one. A volume with no recorded value (created before this existed, or by something else) is **not** trusted as legacy-CLEAN the way an old `.spec` record is — it fails `meta()`, which the caller already treats as case F10 (untrusted member, needs a resync).
- **`ost/session.cpp`** — handlers for the new opcodes.
- **`src/object.cpp`** — per-mirror state machine (IN-SYNC/STALE/SYNCING per `Connection`), quorum checks at open, degraded open, the degradation procedure (F1: suspend acks → bump survivors' metadata → resume), read failover + read-repair, the resync engine (bitmap + sweeper + per-chunk locks), reconnect probes for STALE mirrors. Cross-mirror logic lives in `Object`; `Connection` keeps only per-location retry/reopen.
- **`cli/`** — `rawstor-cli status` (mirror states), `rawstor-cli force-open` / an opts flag (below-quorum start, explicit manual approval), `rawstor-cli resolve` (split brain after force-open/backup restore).

### Implementation stages

1. Metadata + new opcodes + the fsync protocol for metadata.
2. Quorum rules at open + degrade & continue / write freeze + read failover and read-repair.
3. Online resync.
4. (v2+) persistent write-intent bitmap, MDS witness in quorum, stored checksums / scrub, fastest-mirror read selection.
