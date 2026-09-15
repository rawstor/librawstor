# Rawstor MDS design (block storage)

Metadata Storage Target (**MDS/MDT**) design, specialized for the **block
storage** use case: sparse (thin) allocation and large object chunks (1+ GiB).

Status: **approved** (2026-07-06). Supersedes the earlier draft where the
*Decision revalidation* table below says so. Nothing is implemented yet; see
*Implementation stages*.

See also: [Architecture.md](Architecture.md), [Protocol.md](Protocol.md),
`librawstor/docs/mirroring.md` (quorum rules the witness plugs into).

## Requirements, in priority order

0. **Allocation and tracking** — answer "which OST hosts which part of which
   volume" (`getObj` / `getObjPart` / `getFreeOst` of Architecture.md, refined
   below) and generate placements at create/grow time. This is the reason MDS
   exists; everything else layers on top.
1. **Snapshot / version registry** — assign `snap_id`s and remember which
   members hold each snapshot.
2. **Witness** — metadata-only quorum member for client-side mirroring
   (restores auto-start for 2 data mirrors with one OST down; see
   `mirroring.md`, Quorum).

Implementation order follows the same list: chunking first, snapshots second,
witness third. All three are designed here so the later stages land without a
redesign.

## Principles

- **OST side is the durable ground truth.** Every chunk is *self-describing*:
  alongside the chunk data the OST keeps metadata about that chunk itself
  (`chunk_meta`). Losing the MDS map is therefore **not** fatal — it can be
  rebuilt by scanning all OSTs.
- **MDS is an index over that truth.** It is the normal source for
  `openVolume`, but it is recoverable, so v1 runs a single instance.
- **MDS is off the hot path — including the moment of a disk failure.** The
  map is read once at volume open and cached; degrade decisions during I/O are
  made and recorded by the client on the surviving data members only, exactly
  as mirroring does today. The witness is written synchronously only at
  non-hot moments (open / clean close / resync completion); see *Witness*.
- **Redundancy is the client's responsibility** (per Architecture.md). MDS and
  placement only produce *slots*; the client decides what goes in them
  (mirror copies or erasure-coding shards) and does the encode/decode.
- **One wire protocol.** MDS commands are new opcodes in the existing OST
  protocol (`rstr` magic). An OST can therefore serve as a *partial MDS*
  (the shared metadata subset), and a full MDS is a server speaking the same
  protocol without the data opcodes.

Why the explicit map works for block storage: with 1 GiB chunks a 1 TiB volume
has **≤ 1024** map entries (a few KiB), so the map is stored **explicitly**
rather than computed (unlike Ceph/CRUSH). The deterministic placement function
is only the *generator* of placements at create/grow time and the reference
used when rebuilding by scan.

| | Ceph (4 MiB objects) | rawstor block (1+ GiB chunks) |
|---|---|---|
| 1 TiB volume | ~256 000 objects | **≤ 1024 map entries** |
| Per-volume map | huge, computed (CRUSH) | **tiny, stored explicitly** |
| MDS on hot path | — | **no, allocation only** |

## Compatibility stance

There are **no live installations yet**: breaking wire and on-disk formats is
free until the first one. The core decisions here do not lean on backward
compatibility (they would be the same greenfield), but this freedom is used
in four places and spent on one addition:

- **Response frame**: every response becomes `{ int32 res; uint32 len;
  uint64 hash }` + `len` bytes of body — an explicit length field instead of
  overloading `res`, resolving the standing TODO in `protocol.h`. (This is,
  amusingly, the response frame of the rejected separate MDS protocol — the
  frame survives, the magic does not.)
- **No legacy acceptance**: `chunk_meta` starts at `format_version` 1; the
  `.spec` v0 (size-only) acceptance/migration in librawstor is dropped rather
  than carried into the chunked world. Note: `sync_id == 0` is **not** a
  legacy shim and stays — it is the live "blank copy, never part of a sync
  set" marker written at create and relied on by F10 recreate (a blank copy
  with a random `sync_id` would read as split brain at the next open; with
  the current set's `sync_id` it would claim data it does not have).
- **Opcode space**: regrouped into reserved ranges per role (session / data /
  shared metadata / volume) instead of appending to one enum — free today, a
  breaking change after the first install.
- The degenerate-object unification (below) is kept as *design* — one schema,
  one code path — not as a migration bridge; there is nothing to migrate.
- **Spent on: a version handshake.** This freedom ends at the first live
  install, so the mechanism for future breaks is added now, while it costs
  nothing: protocol version + feature bits in the connection handshake
  (`SET_OBJECT` is already the mandatory first command). Partially covers the
  "capabilities negotiation TBD" of Protocol.md.

## Decision revalidation (vs the earlier draft)

| Draft decision | Verdict | Why |
|---|---|---|
| Separate MDS wire protocol, distinct magic `rsmd` | **Changed: single protocol with OST** | An OST doubles as a partial MDS (the witness subset — `SPEC`/`SET_STATE` — already exists on OSTs today); one framing/parsing stack; misconnection safety comes from `-ENOSYS` on unknown opcodes instead of a magic mismatch |
| Explicit stored map (not CRUSH-computed) | Keep | ≤ 1024 entries/TiB; placement function stays the generator |
| Weighted rendezvous (HRW) placement | Keep | deterministic, minimal reshuffle, stateless, O(N) fine at this scale |
| Hand-rolled packed structs, count prefixes, `format_version` | Keep | codebase idiom, no new dependency |
| Chunk identity rides `RawstorOSTFrameBasicBody` unchanged | Keep | see *Chunk identity* |
| Opaque stable `ost_id` (UUID), resolved via topology | Keep | required for HRW stability |
| epoch-fence (client cache vs per-chunk hard gate) | Keep, **collapsed + renamed** | one counter `map_epoch` per volume; the per-slot fence is a stored *watermark* of it, not a second counter; the mirroring per-copy `mirror_epoch` (already shipped) provably cannot be merged in — see *epoch-fence* |
| Shard by `volume_id`; primary + replicated log per shard; reads from any replica | **Replaced in v1: single MDS instance** | witness availability does not require MDS replication (a dead witness = one lost vote); the map is rebuildable by scan; replication is v2, the epoch/CAS model below is compatible with primary+log |

## Chunk identity

```
logical chunk_id  = (volume_id, chunk_offset, version)
physical chunk_id = (volume_id, chunk_offset, version, slot_index)
```

A logical chunk has `width` slots (`slot_index` 0..width-1); see *Redundancy*.
The logical id maps onto the existing `RawstorOSTFrameBasicBody` with no
wire-format change:

```c
struct RawstorOSTFrameBasicBody {
    uint8_t  obj_id[16];   // = volume_id
    uint64_t offset;       // = chunk_offset (logical_index * chunk_size)
    uint64_t val;          // = version / snap_id
} __attribute__((packed));
```

On-OST layout (the slot's home, also where `chunk_meta` lives). `version` is
part of the *logical* identity only: on CoW backends a version materializes as
a **native snapshot of the slot's live volume**, not a separately named one —
naming a volume per version would contradict the snapshot design (stage 2):

| Backend | Slot home + metadata | Versions (`snap_id`) |
|---------|----------------------|----------------------|
| `file://` | `<volume_id>/<offset>#<slot>.dat` + `.spec` sidecar | `-ENOTSUP` in v1 |
| `lvm://`  | thin LV `<volume_id>-<offset>-<slot>`, meta in LVM tags | thin snapshot LV |
| `zfs://`  | zvol `<volume_id>-<offset>-<slot>`, meta in user properties | `@<snap_id>` |

### `chunk_meta` — one schema, two layers

Mirroring (implemented) already stores a per-copy consistency tuple on every
backend (`.spec` / LVM tags / ZFS user properties) and moves it over the wire
as `RawstorOSTFrameMetaBody { size, epoch, sync_id, sync_id_history[4],
state }`. `chunk_meta` **extends** that record with placement identity instead
of inventing a second one:

```
chunk_meta {
  magic, format_version
  // placement identity (new)
  volume_id, logical_index, chunk_size
  version                  // snap_id this slot belongs to; 0 = live
  redundancy               // mirror{R} | ec{k,m} — how to decode
  slot_index
  member_kind              // data | witness — witness records are metadata-only
                           // and are excluded from the map reconstruct
  created_at, project_id
  // per-slot consistency (exists today, per mirroring.md)
  size, state, mirror_epoch, sync_id, sync_id_history[4]
  data_checksum            // per-slot, v3+ (scrub); reserved
  snapshots[]              // version list present on this slot; reserved for stage 2
}
```

A present-day mirrored object is the degenerate case: one chunk
(`logical_index = 0`, `chunk_size = volume size`, `version = 0`), `width = N`.
One schema and one code path for both worlds — kept as design, not as a
migration bridge (no live installations, nothing to migrate; see
*Compatibility stance*).

`chunk_meta` feeds **two** consumers from one source: the OST's local in-RAM
index (`offset → local slot`, built by one backend scan at startup) and the
global MDS reconstruct.

## MDS data model

```
volume_descriptor {
  volume_id, logical_size, chunk_size,
  policy {
    redundancy    = mirror{ copies R } | ec{ data k, parity m },  // width = R | k+m
    failure_domain = server | rack | dc,   // level at which slots must differ
    stripe_width  = K | all,               // locality: over how many OSTs spread
    placement_seed
  },
  project_id, created_at,
  map_epoch                              // monotonic, ++ on any map/descriptor
                                         // change (incl. snapshot, resize)
}

chunk_map[logical_index] = {
  slots: [ {slot_index, ost_id} * width ] // who holds each copy/shard
  // physical existence ("materialized") is an OST fact, not tracked strictly
}

snapshots[snap_id] = {
  created_at,
  members: [ost_id],                     // who actually holds it (see Snapshots)
  view: { logical_index -> version }     // cache over OST-side snapshots
}

witness[volume_id or (volume_id, logical_index)] = {
  state,                                 // CLEAN | DIRTY_OPEN | DIRTY_DEGRADED
  sync_id, sync_id_history[4], mirror_epoch,
  survivors[]                            // only for DIRTY_DEGRADED
}
```

Two classes of state, by recoverability:

- `volume_descriptor` / `chunk_map` / `snapshots` — an **index**; DR = rebuild
  by OST scan (below).
- `witness` records — **not** rebuildable by scan (they *are* the extra vote).
  Losing them degrades availability (auto-start falls back to plain N=2
  rules), never correctness; re-attach is defined in *Witness*.

## MDS API

| Method | When | Hot? |
|--------|------|------|
| `createVolume(size, chunk_size, policy) -> {volume_id, map_epoch}` | once | no |
| `openVolume(volume_id) -> {descriptor, map_epoch, chunk_map}` | at open | **only hot read**, client-cached |
| `resizeVolume(volume_id, new_size)` | grow (v1: grow-only) | no |
| `snapshot(volume_id) -> snap_id` | snapshot | no |
| `updatePlacement(volume_id, index, slots)` | rebalance/recovery | rare |
| `removeVolume(volume_id)` | delete | no |
| witness get/put | open (incl. witness-assisted degraded open) / clean close / resync-complete; async after degrade | no (see Witness) |

Refines `getObj / getObjPart / getFreeOst` from Architecture.md; `getFreeOst`
is subsumed by the placement function + topology (the client never picks OSTs
ad hoc).

> Optimization (optional, v2+): with deterministic placement the client can
> derive placement locally from `{descriptor + exception-list + topology}`,
> pushing MDS even further off the path. Base design returns the explicit map.

## Wire protocol: one protocol, role subsets

Same `rstr` magic, same frame heads, one response frame for everything
(`{res, len, hash}` + body — see *Compatibility stance*). Opcodes live in
reserved ranges per role:

```
0x00    session:         SET_OBJECT                    // handshake, every role
0x01..  data:            READ, WRITE, DISCARD, ALLOCATE, RELEASE, FLUSH
0x20..  shared metadata: SPEC, SET_STATE, LIST_CHUNKS  // the witness subset + scan
0x40..  volume (MDS):    VOL_CREATE, VOL_OPEN, VOL_RESIZE, VOL_SNAPSHOT,
                         VOL_UPDATE_PLACEMENT, VOL_REMOVE, VOL_GET_PLACEMENT
```

- `SET_OBJECT` is the mandatory first command on **every** connection and
  carries the handshake: **protocol version + feature bits** (added now,
  while breaking is free) plus the object binding. On control connections
  (volume commands only) the binding is null — which is why it sits in its
  own *session* group, implemented by every role, not in the data group.
- A server answers `-ENOSYS` to any opcode outside its role — the existing
  convention; this is also the misconnection guard that the separate magic
  used to provide.

Role matrix:

| Opcode group | OST | OST as partial MDS | full MDS |
|---|---|---|---|
| session (`SET_OBJECT`) | yes | yes | yes |
| data (`READ`,`WRITE`,`DISCARD`,`ALLOCATE`,`RELEASE`,`FLUSH`) | yes | yes | no (`-ENOSYS`) |
| per-object/chunk metadata (`SPEC`, `SET_STATE`) — the **witness subset** | yes (today) | yes | yes |
| `LIST_CHUNKS` | yes | yes | yes (serves its own index) |
| volume commands (`CMD_VOL_*`) | no | optional | yes |

Consequence for stage 3: **a witness needs no new server.** A metadata-only
member on a plain `rawstor-ost` already speaks the witness subset.

Example `CMD_VOL_OPEN`:
```
req  body: { volume_id[16], snap_id u64 }               // 0 = live
resp: { res, len, hash }; body:
      { descriptor{...}, nchunks u32,
        entry[nchunks] { version u64, width u8, (slot_index u8, ost_id[16]) * width } }
```

`ost_id` is an **opaque stable UUID** (not host:port) — required for HRW
stability; resolved to an address via topology (v1: static config, see MGS).

## Placement function

Role: `place(volume_id, index, topology) -> [ (slot_index, ost_id) * width ]`.
Used only at create/grow (generate the plan) and at rebalance/recovery (where
to put a rebuilt slot). The MDS map stays authoritative; the function is a
generator.

- **Algorithm: weighted rendezvous (HRW)** hashing — deterministic, capacity-
  weighted, minimal reshuffle on topology change, distinct slots = top-N, no
  state. O(N) per lookup is fine (small N, rare lookups).
- **Topology = tree**: `root -> dc -> rack -> server -> ost(leaf)`. Weights
  aggregate up the tree; `ost_id -> host:port` resolved from the same source
  (v1: static config).
- **Hierarchical HRW** descends the tree, choosing `width` slots so that **no
  failure-domain holds more than `m` shards** (mirror: ≤ 1 copy per domain),
  making a domain loss survivable.

```
place(volume_id, index):
  slots = HRW_choose(width, level=failure_domain, key)  // distinct domains
  for s in slots: ost = HRW_descend_to_leaf(s, key)
  return [(slot_index, ost) ...]
```

- **Locality knob: `stripe_width` stays a number `K`** (the draft's
  alternative `locality_level` is dropped — `K` already spans the whole
  spectrum and a level form can be layered later as sugar over K + topology).
  Slot separation is the independent axis, always at `failure_domain`:

| stripe_width | HRW key | behavior |
|---|---|---|
| `K=1` (local) | `volume_id` only | all chunks -> same OSTs (DRBD-like), still domain-separated |
| `K=all` (spread) | `(volume_id, index)` | each chunk independent (Ceph-like) |
| `K` partial | pool of K by `volume_id`, then `(volume_id, index)` within | stripe over a subset |

- **Unsatisfiable topology hard-fails.** If `R`/`failure_domain` cannot be met
  (need 3 racks, have 2), `createVolume` fails; it does not silently place an
  under-protected volume. The same rule holds at recovery time: if a rebuilt
  slot cannot be placed without violating domain-distinctness, the chunk stays
  explicitly degraded and is reported — an operator may relax the policy, the
  system never does it silently. (Design-by-construction: "protected by
  policy" is an invariant, not a best effort.)

## Redundancy

Placement produces `width` domain-distinct slots; the **client** fills and
reads them per the scheme (encode/decode is client-side):

| Scheme | width | slot content | write | read |
|--------|-------|--------------|-------|------|
| mirror R | `R` | full copy | write all R | read any 1 |
| EC k+m | `k+m` | shard (data/parity) | encode, write k+m | read any k, decode |

- Physical shard size under EC = `chunk_size / k` (e.g. 256 MiB at k=4 for a
  1 GiB logical chunk).
- `mirror` is implemented first; `EC` is a future **policy**, not a redesign —
  the slot model (`width` + `slot_index`) and `chunk_meta.redundancy` already
  carry it.

## I/O path (MDS not involved)

```
client holds the cached map: which OST owns which (logical_index, slot)
  |
  |- splits the request at chunk boundaries ONLY to pick owning OST(s)
  |- encodes per redundancy (mirror: copy; EC: shards)
  '- one connection per (OST, volume):
        SET_OBJECT(volume_id, val = snap_id; 0 = live)   <- once
        READ/WRITE(offset = logical volume offset, len)  <- many, pipelined by cid
              '- OST: offset -> local slot -> backing file/LV/zvol
```

- IO frame **unchanged** — `offset` stays the 64-bit logical volume offset.
- **One connection per (OST, volume)** serves all of that OST's chunks.
- Client needs `chunk_size` only for **routing**, not for addressing inside an OST.

## epoch-fence

One placement counter per volume; the fence is a stored watermark of it, not
a second counter:

- `volume.map_epoch` — the **only** placement counter. ++ on any map change,
  rides in every IO frame (advisory freshness hint), and doubles as the CAS
  token for MDS mutations.
- `slot.fence` on the OST — a **watermark**: the `map_epoch` value at which
  this slot's placement moved away, recorded on the **old** owner
  (migration/recovery only).

`write: if client_map_epoch < slot.fence -> STALE -> client re-reads map ->
retry`. Snapshot and resize bump `map_epoch` but record no watermark on any
slot, so they *cannot* STALE anything — the "no STALE storm on un-migrated
chunks" property is structural, not a convention about when to raise a gate.

### Why `mirror_epoch` does not collapse into it

Merging the mirroring per-copy `mirror_epoch` into the map/fence numbering
fails by counterexample: a degrade bump is written by the client to the
surviving arms only, with no MDS round-trip (the hot-path requirement). If it
shared the fence numbering, the surviving client would either fence *itself*
out (its cached `map_epoch` is now behind the value it just wrote to the
survivors) or need the MDS at the failure moment — both unacceptable. The two
also differ in scope and writer: `map_epoch` is per-volume, MDS-issued, and
versions *placement*; `mirror_epoch` is per slot-set, client-issued, versions
*membership health*, and is part of the durable consistency tuple on arms and
witness. (Within mirroring, `mirror_epoch` vs `sync_id` is likewise left
alone: ancestry is derivable from `sync_id_history`, but the epoch is the
cheap total order and the guard against history-window overflow, and it is
already shipped.)

### Migration / `updatePlacement` sequence

The fence must land on the **old owner** — that is the only OST a stale client
still talks to:

```
1. copy the slot to the new OST (resync machinery, source = an IN-SYNC slot)
2. MDS reserves E' = map_epoch + 1; record E' as slot.fence on the OLD owner (fsync'd)
3. MDS: chunk_map[index] slot -> new ost_id, publish map_epoch = E'
4. (later) release the old slot
```

Counterexample that fixes the order: fence only the *new* OST (or update the
map first) and a client with a cached map keeps writing to the old OST
indefinitely — nothing it touches ever says `STALE`, acknowledged writes land
on a slot the map no longer references, and are lost after step 4. The fence
must carry the *reserved upcoming* epoch: between steps 2 and 3 a stale
client's write hits the fence, re-reads a not-yet-updated map and retries — a
benign transient that resolves at step 3; the reverse order (map before
fence) instead opens a window of silently lost writes.

If the old owner is unreachable (the usual *reason* for the migration), step 2
cannot execute; then the slot may be reassigned only when the old OST is
marked **decommissioned** in the topology. If it ever comes back anyway, its
copy is stale by mirror metadata (`sync_id` ancestry) and is caught at the
mirroring layer — defense in depth, not the primary guard.

## Snapshots (stage 2)

Snapshots are **OST-side CoW** (native zfs/lvm-thin); the MDS only registers
them. Coordination is **client-driven**, per the mirroring identity model:
drain + FLUSH first, so a snapshot is a crash-consistent point across all
members, and only IN-SYNC members participate.

Two-phase, because the OSTs need the `snap_id` before the MDS can know the
snapshot exists:

```
snapshot(volume_id):
  MDS:    VOL_SNAPSHOT begin  -> reserve snap_id
  client: drain in-flight I/O, FLUSH all IN-SYNC members   (point-in-time barrier)
  OST*:   each IN-SYNC member -> backend CoW (zfs snapshot zvol@<snap_id> / lvcreate -s)
  MDS:    VOL_SNAPSHOT commit -> record snapshots[snap_id] { members = the IN-SYNC set },
                                 map_epoch++
  read:   client SET_OBJECT(volume_id, val = snap_id) -> OST serves that version
```

A crash between begin and commit leaves unregistered native snapshots on the
OSTs — the same garbage class as a crashed deletion, reconciled by the
reconstruct scan (below).

- **`version` in chunk identity = `snap_id`** (0 = live). One namespace, no
  separate counter.
- **In-sync snapshots are immutable → they never resync.** A member that was
  STALE at snapshot time simply does not have that snapshot; rejoin/resync
  covers the live version only (v1).
- **Degraded volumes:** the snapshot is taken on the IN-SYNC members only and
  `snapshots[snap_id].members` records exactly who holds it. Snapshot reads
  route only to recorded members. A snapshot may therefore have less
  redundancy than the volume policy; this is surfaced in status, not silently
  repaired (v1; a repair = copy of an immutable version, safe to add later).
- **Deletion:** MDS unregisters first (no new readers), then fan-out destroy
  on members; the reconstruct scan reconciles leftovers from a crash between
  the two steps (an unreferenced snapshot version found on an OST is garbage,
  collectable).
- **`file://` backend has no CoW** → `snapshot` on a volume with `file://`
  members fails with `-ENOTSUP` in v1 (no fallback copies behind the caller's
  back).

**v1 notes (shipped):**

- **Classic LVM is `-ENOTSUP` too.** This section says lvm-*thin* for a
  reason: a classic LVM snapshot needs a preallocated COW area — a hidden
  full-size copy is exactly the fallback ruled out above. CoW on LVM waits
  for an lvm-thin backend. zfs is the v1 CoW backend: snapshots are
  `<parent>/<uuid>@s<snap_id>` (the `@s<id>` name *is* the version key —
  nothing stored twice; `snapdev=visible` is set with every snapshot so
  each one that exists is also openable), read via
  `/dev/zvol/…@s<id>`, read-only at the device level too.
- **Reads:** `<target>@<snap_id>` on the regular open
  (`mds://host:port/<volume_id>@<snap_id>`, `ost://…/<uuid>@<snap_id>`);
  the wire carries the version in the `val` field SET_OBJECT and SPEC
  already had. Opening a snapshot **bypasses the mirror state machine
  entirely** — no metadata compare, no quorum, no barriers, no resync, no
  probe. That is not just an optimization: the frozen copy state is DIRTY
  (snapshots are taken mid-session), which the live open logic would
  treat as a crash to recover from. Immutability is what makes the bypass
  sound: one reachable member serves, writes fail with EROFS.
- **The two-phase begin is durable and never reuses an id** (per-volume
  monotonic `next_snap_id`, fsync'd at begin): leftovers of a crashed
  attempt can never alias a later snapshot. The reconstruct scan re-fences
  the counter from every version it sees — garbage included.
- **Chunks are CoW'd in descending index order** (chunk 0 last). A crashed
  attempt therefore always leaves a hole at the low indices, and the
  reconstruct scan can never mistake a partial leftover for a complete
  (legitimately shorter, pre-resize) snapshot: a contiguous `0..max`
  version proves itself, because index 0 exists only when every higher
  index was already done. Complete versions found by the scan are
  registered even if the commit never landed — they are indistinguishable
  from committed ones and just as consistent (drain + FLUSH preceded the
  CoWs); holed versions stay unregistered garbage.
- **Volume deletion order matches snapshot deletion**: the MDS
  unregisters the map first — which is also where "the volume still has
  snapshots" refuses with `-EBUSY` *before* any data is touched — then
  the chunk objects are destroyed.
- **v1 caveat:** the CLI-driven snapshot assumes no concurrent writer —
  the drain barrier is the writing client's duty and lives in its
  process; a vhost/QEMU flush hook is future work. Snapshot redundancy
  status surfacing is still TODO.

## Witness (stage 3)

A witness is a **metadata-only member** of a mirrored object's quorum: it
stores the consistency tuple (`state`-like record, `sync_id`,
`sync_id_history`, `mirror_epoch`) and holds no data. For N=2 data mirrors it
is the third vote that restores auto-start with one OST down. Implementation:
any server speaking the witness subset (`SPEC`/`SET_STATE`) — a plain OST, an
OST doubling as partial MDS, or the MDS itself. The member appears in the
target list like any other member; data I/O and resync skip it. Its stored
record carries `member_kind = witness` (see `chunk_meta`), so a
`LIST_CHUNKS` reconstruct scan never mistakes the witness host for a data
slot.

**Hard requirement: the witness is not on the failure hot path.** When a data
member dies mid-session, the client records the new generation on the
surviving data members only — exactly today's degrade barrier, no witness
round-trip before acks resume. The witness copy of that update is
**asynchronous, best-effort** (retried opportunistically for the rest of the
session).

### When the witness is written synchronously

Only at non-hot moments, where a round-trip is already acceptable:

| Moment | Witness record written |
|---|---|
| open with write intent | `DIRTY_OPEN { sync_id }` (same barrier that marks data copies DIRTY) |
| witness-assisted degraded open | `DIRTY_DEGRADED { new sync_id, survivors }` — **before the first write ack** |
| resync completion / `resolve` | new `sync_id`, record kind back to `DIRTY_OPEN` — the session is still open (same barrier that promotes the SYNCING copy) |
| clean close | `CLEAN { final sync_id }` |

If a synchronous witness write fails, the session continues (the witness is
never required for a session that has a data quorum) — the record is simply
out of date and the witness abstains later; the client keeps retrying in the
background.

### Voting rule

The witness's vote counts **only when its record is provably consistent**:

1. **`CLEAN` witness**: approves auto-start of a `CLEAN` data member with the
   **same `sync_id`** — `{arm, W}` is a quorum. This is the headline case:
   volume closed cleanly, one OST died between sessions.
2. **`DIRTY_DEGRADED { survivors }` witness** (the async degrade update did
   land, or a witness-assisted degraded open wrote it): approves auto-start
   **only of the single recorded survivor** (`|survivors| = 1`) whose
   `sync_id` matches. Rationale: once the surviving set is a single member, no
   further generation bump can happen away from it (a lone survivor has no one
   left to exclude; with N≥3, ≤N/2 survivors freeze writes), and resync
   completion — the only other bump — writes the witness synchronously.
3. **Anything else — the witness abstains**: `DIRTY_OPEN`,
   `DIRTY_DEGRADED` with `|survivors| > 1`, a `sync_id` it cannot relate, or
   no record at all. Auto-start then falls back to the plain data-only quorum
   rules of `mirroring.md`. Abstention is a pure availability cost, never a
   correctness one.

Independently of voting, a witness that knows a **newer** `sync_id` than a
reachable arm vetoes that arm (ancestry via `sync_id_history` — which is why
the witness record carries the history): the arm is stale, and the client gets
a precise error ("newest data is on X, which is down") instead of a wrong
start.

### Counterexamples that shaped the rules

These are the automatic-path holes each rule exists to close (N=2, members
A, B, witness W, generations S1 → S2):

- **(i) Why the open-time write is synchronous.** Suppose it weren't: clean
  state S1 everywhere, session opens (W untouched, still `CLEAN S1`), B dies,
  degrade puts S2 on A, client crashes, A's host dies too. Auto-start sees
  `{B: DIRTY S1, W: CLEAN S1}` — a match; rule 1 would approve B, orphaning
  acknowledged S2 writes on A. **Split brain.** With the synchronous
  `DIRTY_OPEN` mark, W abstains and the start is refused — correct, the only
  current data is on A.
- **(ii) Why a witness-assisted degraded open bumps the generation on W
  synchronously.** `{A, W}` start on S1, bump to S2 recorded on A only; if W
  keeps `CLEAN S1`, then after this client is gone, `{B, W}` matches on S1 and
  starts the old branch — two divergent histories from one witness. Writing
  `DIRTY_DEGRADED {S2, survivors={A}}` on W before the first ack closes it
  (this is an open, not a failure moment — the hot-path requirement is
  respected).
- **(iii) Why `DIRTY_OPEN` never approves.** After a crash everything is
  `DIRTY` at S1 — indistinguishable, from `{B, W}` alone, from "degrade of B
  happened and the async update never landed". Approving B in the first case
  would be fine; in the second it is split brain. The witness cannot tell them
  apart, so it must abstain: after a crash, auto-start needs the full data
  quorum (both arms), exactly like plain N=2 — no regression.
- **(iv) Why `DIRTY_DEGRADED` approves only a lone survivor.** With N=3 and a
  landed update `{S2, survivors={A,C}}`, a later degrade among the survivors
  (C excluded, S3 on A, async update lost again) leaves C matching the
  witness's S2 — approving C would orphan S3. `|survivors| = 1` removes the
  possibility by construction.

### Failure/decision table (N=2 + W)

| Situation at open | Records seen | Outcome |
|---|---|---|
| Clean shutdown, B down | A `CLEAN S1`, W `CLEAN S1` | rule 1: start on `{A,W}`, bump S2 on A **and** W (rule ii) |
| Clean shutdown, A and B down | W only | refuse — a witness holds no data |
| Crash, no degrade | A,B,W all `DIRTY S1` | W abstains (rule iii); need both arms; F5 winner rules apply |
| Crash after degrade of B, A up | A `DIRTY S2`, B `DIRTY S1`, W stale | data-only quorum `{A,B}`: ancestry picks A, resync B — witness not needed |
| Crash after degrade of B, A down, async update **not** landed | B `DIRTY S1`, W `DIRTY_OPEN S1` | W abstains → refuse. Correct: acknowledged S2 exists only on A |
| Same, async update **landed** | B `DIRTY S1`, W `DIRTY_DEGRADED {S2, {A}}` | W vetoes B (ancestor) with a precise error; if A is reachable instead: rule 2 approves A |
| W restored from backup / reprovisioned empty | arm `CLEAN S1`, W old or empty | mismatch / no record → abstain; client re-attaches W (rewrites the record) at the next open/close it performs with a valid quorum |
| W down entirely | — | plain N=2 semantics for the session; sync witness writes fail soft |

Runtime behavior is unchanged from `mirroring.md`: N=2 may still continue on a
single survivor after a mid-session member loss (the abandoned arm is
`DIRTY`/ancestor, and per the table above no witness state can auto-start it
alone), and the degrade barrier still touches only the survivors.

### Witness in the chunked world

Witness records are per `(volume_id, logical_index)` — chunks degrade
independently in general. With `stripe_width K=1` (all chunks on the same
OSTs) member loss degrades every chunk identically; the record may be stored
once per volume with the index dimension collapsed (an optimization of the
same schema, decided at descriptor level).

## MDS server, v1: single instance

One `rawstor-mds` process, no replication in v1. Justification: the map is
rebuildable by scan; witness loss costs one vote (availability), not
correctness; and a witness for the *data* quorum does not itself need to be
replicated. Replication (primary + log shipping, reads from any replica with
the `map_epoch` fence catching lagging reads) is reserved for v2 — the
epoch/CAS data model here is already compatible with it.

### Storage engine

Requirements: kilobyte-scale data, rare mutations, `fsync`-grade durability
per mutation (witness records above all), crash-atomicity, one deployable
binary.

| Option | Verdict |
|---|---|
| PostgreSQL | **Rejected.** An external server and its operational surface for kilobytes of state; breaks "MDS = one binary"; v2 replication must follow the epoch model anyway, not a DBMS's |
| Own format (append-log + snapshot, or per-volume files à la `.spec`) | Viable, zero dependencies, codebase style — but the fsync-ordering / torn-write / atomic-rename protocol must be designed and proven by us, and every schema change is manual |
| **SQLite** (WAL mode; `synchronous=FULL` for witness and map mutations) | **Chosen.** Crash-safety and transactional atomicity by construction rather than by our own proof; trivial schema migrations; ubiquitous, dependency-wise in the same class as liburing/xxhash. Mutations are rare — they run on a worker thread reporting back to the I/O queue, the same pattern as the `file://` control plane |

The asymmetry of the two state classes (map = recoverable cache, witness =
authoritative votes) does not force a hybrid: SQLite serves both, with the
witness tables being the reason `synchronous=FULL` is non-negotiable.

## Reconstruct / DR

```
rebuild the map:
  get the OST roster from topology (v1: static config)
  for each OST: CMD_LIST_CHUNKS -> [(physical chunk_id, chunk_meta)]
  drop member_kind = witness records (metadata-only, not slots)
  group by (volume_id, version): version 0 -> live chunk_map,
                                 version = snap_id -> snapshot view
  within each group: order by logical_index
  -> reassembled maps (+ snapshot views)
```

This same scan doubles as a scrub / consistency check. Witness records are
**not** reconstructed (see the two state classes); after a from-scratch
rebuild every witness abstains until clients re-attach records in the course
of normal opens/closes.

**v1 notes (shipped as `rawstor-mds --reconstruct`, scan before serving):**

- **No partial scans, by construction:** every OST of the topology must
  answer `LIST_CHUNKS` or the reconstruct aborts. A half scan would
  silently drop the unanswered OST's live copies from the map; an OST that
  is really gone is removed from the topology first — an explicit
  operator decision, not a timeout.
- **The map is restored, the policy knobs are not.** `failure_domain`,
  `stripe_width` and the placement seed are deliberately not persisted on
  chunks (descriptor-only state); the rebuilt descriptor gets the weakest
  constraints (per-OST domain, spread), `width` comes from the records.
  Existing chunks keep their placement — the map is explicit — so only a
  post-disaster resize places new chunks under the reset policy.
- **Degraded chunks reconstruct degraded:** a chunk with some copies lost
  keeps its surviving slots and `VOL_OPEN` serves them (the mirror layer
  owns the redundancy question). A chunk with **no** surviving copy fails
  the whole reconstruct loudly — the MDS must not pretend the volume is
  whole, and it cannot invent data.
- The tail chunk's stored size may be rounded up by a block backend (LVM
  extent, ZFS volblocksize); the reconstructed `logical_size` takes the
  smallest copy, clamped to `chunk_size` — never smaller than what was
  written.
- Snapshot-version records are skipped (stage 2); the full MDS serving
  `LIST_CHUNKS` from its own index (the scrub comparison) is not
  implemented yet.
- Wire shape: the response payload is `res` chunk_meta records (the SPEC
  meta body with `obj_id` = the physical id), bounded by the same 64 MiB
  cap as the data commands.

## Protocol deltas (to Protocol.md)

- New shared opcode `CMD_LIST_CHUNKS -> [(physical chunk_id, chunk_meta)]` —
  reconstruct / scrub.
- New MDS opcodes `CMD_VOL_*` (same `rstr` command space; `-ENOSYS` outside a
  server's role); opcodes regrouped into reserved ranges per role.
- Unified response frame `{res, len, hash}` + body for **all** commands
  (breaking change, free pre-install; resolves the `protocol.h` TODO).
- `SET_OBJECT` handshake gains protocol version + feature bits.
- `+uint64_t map_epoch` in the IO frame — epoch-fence.
- `SET_OBJECT`: `val` = `snap_id` (0 = live); `obj_id` = `volume_id`.
- Semantics: IO `offset` = logical volume offset (OST resolves to a local slot).
- Witness subset = existing `SPEC` / `SET_STATE`; the meta body is extended
  directly with the record kind (`DIRTY_OPEN` / `DIRTY_DEGRADED`) and
  `survivors[]` — no parallel opcodes, no legacy meta-body acceptance.
- Dropped in stage 1 (no live installations): `.spec` v0 acceptance/migration
  and the client-side tolerance of `-ENOSYS` from `SET_STATE` (a member that
  cannot record metadata must degrade, not silently weaken the barrier).
  `sync_id == 0` stays: it is the blank-copy marker, not a compat shim (see
  *Compatibility stance*).

## Implementation stages

1. **Chunking**: `CMD_VOL_CREATE/OPEN/RESIZE/REMOVE`, HRW placement + topology config,
   explicit map in MDS (SQLite), client-side routing, `map_epoch` + fence watermark,
   `CMD_LIST_CHUNKS` + reconstruct.
2. **Snapshots**: `CMD_VOL_SNAPSHOT`, `version`/`snap_id` in chunk identity,
   member-set registry, deletion, `-ENOTSUP` on `file://`.
3. **Witness**: metadata-only member in the target list, witness record kinds
   + voting rules in the client quorum logic, async post-degrade updates,
   re-attach.
4. **v2+**: MDS replication (primary + log), EC policy, persistent
   write-intent bitmap interplay, snapshot redundancy repair, stored
   checksums / scrub.

## Open questions

- **Auth / capabilities** — TBD at the protocol level (OST and MDS alike).
- **EC details** — codec, read-repair, partial-stripe writes. Client-side
  mechanics; the slot model and `chunk_meta.redundancy` already reserve the
  room.
- **Resize: shrink** — v1 is grow-only; shrink interacts with placement GC
  and snapshots, revisit later.
- **MGS as a service** — v1 uses a static topology config; whether a dynamic
  MGS role (roster + topology + MDS address) is ever needed, and how refresh
  works, is deferred.
- **Witness records at N≥3 with `|survivors| > 1`** — the witness abstains
  today (rule 3); a finer rule would need the degrade chain recorded on the
  witness synchronously, which conflicts with the hot-path requirement.
  Revisit only if N≥3 witness-assisted starts turn out to matter.
