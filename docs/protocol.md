# Rawstor wire protocol

## Status

Legend: ✅ implemented · 🟡 partial · ❌ not implemented yet.

| Area | Status | Where |
|---|---|---|
| Frame head, `rstr` magic, `cid` pipelining | ✅ | `include/rawstor/protocol.h` |
| Response `hash` (xxh3 with libxxhash) | ✅ | `librawstd/src/hash.c` |
| Session: `SET_OBJECT` | ✅ | OST `ost/src/client.cpp`, MDS `mds/src/client.cpp` |
| Data: `READ` `WRITE` `DISCARD` `ALLOCATE` `RELEASE` `FLUSH` `WRITE_ZEROES` | ✅ | OST server + `src/ost_backend.cpp` |
| Metadata: `META` `SET_CONFIG` `LEAVE` `CREATE_VERSION` `LIST_VERSIONS` | ✅ | OST server + `src/ost_backend.cpp` |
| `LIST`, `LOCATION_INFO` | ✅ | OST and MDS servers, both clients |
| Object: `OBJ_CREATE` `OBJ_OPEN` `OBJ_RESIZE` `OBJ_REMOVE` | ✅ | MDS server + `src/mds_client.cpp` |
| Object versions: `OBJ_COMMIT_VERSION` `OBJ_REMOVE_VERSION` `OBJ_LIST_VERSIONS` | ✅ | MDS server + `src/mds_client.cpp` |
| `idempotency_key` on mutating `OBJ_*` | ✅ | `mds/src/store.cpp` (`applied_mutations`) |
| `-ENOSYS` for commands outside a server's role | ✅ | `ost/src/client.cpp`, `mds/src/client.cpp` |
| Protocol version + feature bits in the `SET_OBJECT` handshake | ❌ | planned in [MDS design](mds.md) |
| Explicit `len` field in the response (`{res, len, hash}`) | ❌ | `res` still carries the payload size |
| `map_epoch` in the IO frame (epoch-fence) | ❌ | planned in [MDS design](mds.md) |
| Auth / capabilities | ❌ | open question |

One binary protocol is spoken by every rawstor server role: `rawstor-ost`
(object storage) and `rawstor-mds` (metadata server). The authoritative
definition is [`include/rawstor/protocol.h`](../include/rawstor/protocol.h);
this page describes the same layouts for a reader.

- **Transport:** a stateful TCP connection.
- **Byte order:** host order, i.e. little-endian on every supported platform.
- **Structs:** packed (no padding, no reserved fields), with every multi-byte
  field on its natural alignment inside the struct. Every struct's size is
  checked at compile time.
- **Magic:** `0x72737472` (`"rstr"` in ASCII) opens every frame, as a sanity
  and endianness check.
- **Names:** `RawstorFrame*` for frames and payloads any role may use,
  `RawstorFrameObj*` for the payloads of the object (`OBJ_*`) commands.

In the diagrams below every row is 8 bytes: the left column is the row's
byte offset, the ruler on top each byte's position within the row. A
field's height is its size (a 64-bit field takes one row, a 16-byte id
two), fields smaller than 8 bytes share a row, and a `~` edge marks data
that follows the struct.

## Connection

A client may pipeline requests: each carries a `cid` (command id) and its
response echoes it back, so responses are matched by `cid`, not by order.

The first request on a connection is `SET_OBJECT`. On an OST it binds the
connection to one object (one chunk of it, one version of it); the I/O
commands then act on that object. On the MDS it is a plain handshake. A
server answers any command outside its role with `res = -ENOSYS`.

## Frame head

Every request and every response starts with the same 8-byte head.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +-------------------------------------------+---------------------+---------------------+
  0  |              uint32_t magic               |    uint16_t cmd     |    uint16_t cid     |
     |                                           |                     |                     |
     +-------------------------------------------+---------------------+---------------------+
```

## Commands

One command space for every role, grouped into ranges: `0x00` session (every
role), `0x01..0x1f` data (OST), `0x20..0x3f` metadata shared by OST and MDS,
`0x40..0x5f` object (MDS). `SET_CONFIG` and `META` predate the grouping and
keep `0x0b`/`0x0c`.

| cmd | name | role | request payload | response payload |
|---|---|---|---|---|
| `0x00` | `SET_OBJECT` | all | Basic (`val` = open flags, e.g. `RAWSTOR_READONLY`) | — |
| `0x01` | `READ` | OST | IO | data (`res` bytes) |
| `0x02` | `WRITE` | OST | IO, then `len` bytes of data | — |
| `0x03` | `DISCARD` | OST | IO | — |
| `0x04` | `ALLOCATE` | OST | Allocate | — |
| `0x05` | `RELEASE` | OST | Basic (non-nil `version_id`: that version only) | — |
| `0x06` | `LIST` | OST, MDS | List | List rows |
| `0x08` | `LOCATION_INFO` | OST / MDS | Basic (unused) | `RawstorLocationInfo` |
| `0x09` | `FLUSH` | OST | Basic (unused) | — |
| `0x0a` | `WRITE_ZEROES` | OST | IO (`flags`: `SYNC`, `UNMAP`) | — |
| `0x0b` | `SET_CONFIG` | OST | SetConfig | — |
| `0x0c` | `META` | OST | Basic (`offset` = chunk offset, `version_id`, nil = live) | Meta |
| `0x0d` | `CREATE_VERSION` | OST | Basic (`version_id` = new version) | — |
| `0x0e` | `LIST_VERSIONS` | OST | Basic (`offset` = chunk offset) | Version rows |
| `0x0f` | `LEAVE` | OST | Basic (unused) | — |
| `0x10` | `SYNC_PREPARE` | OST | SyncPropose (`ballot` only) | SyncReply |
| `0x11` | `SYNC_ACCEPT` | OST | SyncPropose | SyncReply |
| `0x40` | `OBJ_CREATE` | MDS | ObjCreate | ObjCreated |
| `0x41` | `OBJ_OPEN` | MDS | Basic (`version_id`, nil = live) | ObjDescriptor + chunks |
| `0x42` | `OBJ_RESIZE` | MDS | ObjOp (`val` = new size) | ObjResized |
| `0x43` | `OBJ_REMOVE` | MDS | ObjOp | ObjDescriptor + chunks (the removed map) |
| `0x45` | `OBJ_COMMIT_VERSION` | MDS | ObjCommitVersion + members | ObjVersionCommitted |
| `0x46` | `OBJ_REMOVE_VERSION` | MDS | ObjOp (`version_id`) | ObjVersionMember records |
| `0x47` | `OBJ_LIST_VERSIONS` | MDS | Basic | Version rows |

Ids (`object_id`, `version_id`, `ost_id`, ...) are 16-byte UUIDs; a nil
`version_id` means the live version. Object and version ids are generated by
the client.

Every mutating `OBJ_*` request (`OBJ_CREATE`, `OBJ_RESIZE`, `OBJ_REMOVE`,
`OBJ_COMMIT_VERSION`, `OBJ_REMOVE_VERSION`) carries an `idempotency_key`: a UUID the client
generates once per operation and keeps across its retries. The MDS records
the result of the first request that applies an `idempotency_key` and answers any
repeat of it with that same result instead of applying it again, so a
request resent after a lost reply is safe (see
[MDS design](mds.md), "Idempotent mutations"). Replies that a retry needs
in order to finish the client's side of the operation carry it:
`OBJ_RESIZE` the chunk count it grew from, `OBJ_REMOVE` the map the object
had.

## Responses

Every response is the head followed by a 12-byte body; a payload, if any,
follows right after.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +-------------------------------------------+---------------------+---------------------+
  0  |              uint32_t magic               |    uint16_t cmd     |    uint16_t cid     |
     |                                           |                     |                     |
     +-------------------------------------------+---------------------+---------------------+
  8  |                                     uint64_t hash                                     |
     |                                                                                       |
     +-------------------------------------------+-------------------------------------------+
 16  |                int32_t res                |          payload (res bytes)...           |
     |                                           |                                           |
     +-------------------------------------------+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
```

- `res < 0` is `-errno`; no payload follows.
- `res >= 0` is the payload size in bytes (for `READ`/`WRITE`/`DISCARD`/
  `WRITE_ZEROES`, the number of bytes handled); `0` means no payload.
- `hash` covers the payload (the data, for `READ`) and is checked by the
  receiver: xxh3 when built with libxxhash, 0 otherwise and whenever the
  sender doesn't compute one (the MDS never does).

## Request payloads

### Basic — 48 bytes

Shared by every command that only names an object: `SET_OBJECT`, `RELEASE`,
`CREATE_VERSION`, `META`, `LOCATION_INFO`, `FLUSH` and the MDS's `OBJ_OPEN`. `offset` is the chunk offset of
the object `object_id` names (0 for a plain object); `version_id` binds
a version for `SET_OBJECT`, `RELEASE`, `CREATE_VERSION`, `META` and `OBJ_OPEN`
(nil = live); `val` is command-specific.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                 uint8_t object_id[16]                                 |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                    uint64_t offset                                    |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 24  |                                                                                       |
     |                                uint8_t version_id[16]                                |
     |                                                                                       |
 32  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 40  |                                     uint64_t val                                      |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
```

### IO — 21 bytes

`READ`, `WRITE`, `DISCARD`, `WRITE_ZEROES` on the bound object. `hash`
covers the data that follows a `WRITE` (same hash as a response's), 0
otherwise. `flags`:
`RAWSTOR_FLAG_SYNC` (durable before the response; `WRITE`, `WRITE_ZEROES`),
`RAWSTOR_FLAG_UNMAP` (may deallocate; `WRITE_ZEROES`).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                    uint64_t offset                                    |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
  8  |                                     uint64_t hash                                     |
     |                                                                                       |
     +-------------------------------------------+----------+--------------------------------+
 16  |               uint32_t len                |  flags   |         WRITE data...          |
     |                                           |          |                                |
     +-------------------------------------------+----------+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
```

### List — 20 bytes

`limit` ids per page, starting after `token_id` (nil = from the start).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                 uint8_t token_id[16]                                  |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +-------------------------------------------+-------------------------------------------+
 16  |              uint32_t limit               |
     |                                           |
     +-------------------------------------------+
```

### Config — 312 bytes

The chunk's configuration (`RawstorObjectConfig`): its sync set, the
writer running the resync of the syncing member (`resync_owner`, 0 when
none) and every member's role, `nroles` entries of `enum RawstorObjectMemberRole` (0
unknown, 1 in-sync, 2 syncing, 3 excluded), the rest zero. Carried in
SetConfig and Meta; see [mirroring](mirroring.md#states-and-roles).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                    uint64_t epoch                                     |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
  8  |                                   uint64_t sync_id                                    |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                            uint64_t sync_id_history[0..3]                             |
     |                                      (32 bytes)                                       |
     +---------------------------------------------------------------------------------------+
 48  |                                 uint64_t resync_owner                                 |
     |                                                                                       |
     +----------+----------------------------------------------------------------------------+
 56  |  nroles  |                              uint8_t roles[255]                            |
     |          |                                    ...                                     |
     +----------+----------------------------------------------------------------------------+
312
```

### Ballot — 16 bytes

A ballot of the configuration register (`RawstorObjectBallot`):
`(counter, proposer)`, ordered by counter, then by proposer
([CASPaxos](caspaxos.md)).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                   uint64_t counter                                    |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
  8  |                                   uint64_t proposer                                   |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
16
```

### SetConfig — 337 bytes

Records the chunk's configuration on one copy (`SET_CONFIG`). The copy's
own state is not set: the copy keeps it ([mirroring](mirroring.md#dirty-clean-and-lost)),
but for `flags` bit 0, `RAWSTOR_CONFIG_CLEAR_LOST`, which turns a `LOST`
copy `CLEAN` (no session open for writing) or `DIRTY`. A server with
several locations keeps no record of the copy it is and answers `-ENOSYS`
([mirroring](mirroring.md#one-copy-per-server)). The copy's ballots stay
as they are: only the register's own requests change them.

`LEAVE` (Basic, unused) is a session's clean departure from the object it
set: the server closes it cleanly, and a copy with no session open for
writing left marks itself `CLEAN`. A session that wrote and ends any other
way -- disconnect, a new `SET_OBJECT` -- leaves a `DIRTY` copy `LOST`.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                 uint8_t object_id[16]                                 |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                 uint64_t chunk_offset                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 24  Config (312 bytes)
     +----------+
336  |  flags   |
     |          |
     +----------+
337
```

### SyncPropose — 373 bytes

The two requests of a chunk's configuration register
([multi-attach](multiattach.md#the-register-caspaxos),
[CASPaxos](caspaxos.md)). `SYNC_PREPARE` asks the member to promise
`ballot` and leaves the rest zero. `SYNC_ACCEPT` asks it to accept the
register's value -- the Config -- under `ballot`, and to promise `next` on
success (zero for none). `flags` bit 0 is `ALONE`: the member refuses with
`-EBUSY` while more than `sessions` sessions have the copy open for
writing, or while the copy is `LOST`. A server with several locations
answers `-ENOSYS`.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                 uint8_t object_id[16]                                 |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                 uint64_t chunk_offset                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 24  Ballot ballot (16 bytes)
 40  Ballot next (16 bytes)
 56  Config (312 bytes)
     +-------------------------------------------+----------+
368  |              uint32_t sessions            |  flags   |
     |                                           |          |
     +-------------------------------------------+----------+
373
```

### Allocate — 44 bytes

Creates one copy of one chunk. `chunk_shift` is `log2(chunk_size)`, 0 for an
unchunked object; `stripe_width`/`failure_domain`/`width`/`member_role` are the
chunk's placement identity, stored with it.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                 uint8_t object_id[16]                                 |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                 uint64_t chunk_offset                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 24  |                                     uint64_t size                                     |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 32  |                                 uint64_t stripe_width                                 |
     |                                                                                       |
     +----------+----------+----------+----------+-------------------------------------------+
 40  |  chunk_  | failure_ |  width   | member_  |
     |  shift   |  domain  |          |   role   |
     +----------+----------+----------+----------+
```

## Response payloads

### List rows — 24 bytes each

One row per (id, chunk offset); an id with several chunks spans consecutive
rows. The MDS answers one row per `mds://` object, chunk offset 0 (the
object is addressed whole). The **last** row is always the resume cursor for the next page (a nil id
once nothing is left), never a result. An empty payload means the far end is
already exhausted.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                    uint8_t id[16]                                     |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                 uint64_t chunk_offset                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
```

### Version rows — 16 bytes each

`LIST_VERSIONS`' and `OBJ_LIST_VERSIONS`' answer: one row per version id,
in no particular order. An empty payload means the object has no versions
(always, on a backend without them).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                uint8_t version_id[16]                                |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
```

### Meta — 360 bytes

Everything about one stored copy: its size, its placement identity, its own
state (`CLEAN`, `DIRTY`, `LOST`), how many sessions have it open for
writing right now (`writers`), and the chunk's configuration as last set on
it (a [Config](#config--312-bytes), at offset 16), and the copy's
replica of the register's ballots: the highest it promised and the one
its Config was accepted under. A server with several locations reports a
zero Config and zero ballots.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                     uint64_t size                                     |
     |                                                                                       |
     +----------+----------+----------+----------+-------------------------------------------+
  8  |  state   |  chunk_  |  width   | member_  |              uint32_t writers             |
     |          |  shift   |          |   role   |                                           |
     +----------+----------+----------+----------+-------------------------------------------+
 16  Config (312 bytes)
328  Ballot promised (16 bytes)
344  Ballot accepted (16 bytes)
360
```

### SyncReply — 361 bytes

`SYNC_PREPARE`/`SYNC_ACCEPT`'s reply, sent whether the member promised or
accepted (`ok` = 1) or refused (`ok` = 0): its whole record, a
[Meta](#meta--360-bytes), follows at offset 1, so a refused proposer sees
the actual value.

```text
     +0         +1
     +----------+--------------------------------------
  0  |    ok    |  Meta (360 bytes)
     +----------+--------------------------------------
361
```

### RawstorLocationInfo — 16 bytes

`uint64_t used`, `uint64_t total` (see `<rawstor/location.h>`).

## Object (MDS) payloads

### ObjPolicy — 19 bytes

Embedded in ObjCreate and ObjDescriptor, at an 8-byte offset in both; the
`chunk_shift` that follows it there rounds its 3 trailing bytes out to 4, so
ObjDescriptor's `nchunks` stays aligned.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                 uint64_t stripe_width                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
  8  |                                uint64_t placement_seed                                |
     |                                                                                       |
     +----------+----------+----------+------------------------------------------------------+
 16  |redundancy|  width   | failure_ |
     |          |          |  domain  |
     +----------+----------+----------+
```

### ObjCreate — 60 bytes

`chunk_shift` is `log2(chunk_size)`; an mds:// object's `chunk_size` is always
a nonzero power of two, so 0 (and anything from 64 on) is rejected.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                    uint8_t id[16]                                     |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                                                                       |
     |                              uint8_t idempotency_key[16]                              |
     |                                                                                       |
 24  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 32  |                                 uint64_t logical_size                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 40  |                                  policy.stripe_width                                  |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 48  |                                 policy.placement_seed                                 |
     |                                                                                       |
     +----------+----------+----------+----------+-------------------------------------------+
 56  |redundancy|  width   | failure_ |  chunk_  |
     |          |          |  domain  |  shift   |
     +----------+----------+----------+----------+
```

ObjCreated and ObjVersionCommitted are a single `uint64_t map_epoch`.

### ObjOp — 56 bytes

`OBJ_RESIZE` (`val` = the new size), `OBJ_REMOVE` and `OBJ_REMOVE_VERSION`
(`version_id` = the version to remove); fields a command doesn't use are
0/nil.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                    uint8_t id[16]                                     |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                                                                       |
     |                              uint8_t idempotency_key[16]                              |
     |                                                                                       |
 24  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 32  |                                                                                       |
     |                                uint8_t version_id[16]                                |
     |                                                                                       |
 40  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 48  |                                     uint64_t val                                      |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
```

### ObjResized — 12 bytes

`OBJ_RESIZE`'s reply: the new `map_epoch` and the chunk count the object grew
from, so a retried resize still knows which chunks it has to create.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                  uint64_t map_epoch                                   |
     |                                                                                       |
     +-------------------------------------------+-------------------------------------------+
  8  |           uint32_t old_nchunks            |
     |                                           |
     +-------------------------------------------+
```

### ObjDescriptor — 56 bytes, then the chunk map

`OBJ_OPEN`'s reply (and `OBJ_REMOVE`'s: the map the object had): the
descriptor, then `nchunks` chunk entries, each a
`uint8_t width` followed by `width` slots. A slot is 19 bytes followed by
`location_len` bytes of its OST's location URI (e.g. `ost://host:7777`, not
null-terminated); `location_len` is 0 when the topology no longer lists that
OST.

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                    uint8_t id[16]                                     |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                 uint64_t logical_size                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 24  |                                  uint64_t map_epoch                                   |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 32  |                                  policy.stripe_width                                  |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 40  |                                 policy.placement_seed                                 |
     |                                                                                       |
     +----------+----------+----------+----------+-------------------------------------------+
 48  |redundancy|  width   | failure_ |  chunk_  |             uint32_t nchunks              |
     |          |          |  domain  |  shift   |                                           |
     +----------+----------+----------+----------+-------------------------------------------+
```

Each chunk entry:

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +----------+----------------------------------------------------------------------------+
  0  |  width   |                               width slots...                               |
     |          |                                                                            |
     +----------+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
```

Each slot:

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                  uint8_t ost_id[16]                                   |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------+----------+------------------------------------------------------+
 16  |uint16_t location_len|slot_index|                     location...                      |
     |                     |          |                                                      |
     +---------------------+----------+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
```

### ObjCommitVersion — 52 bytes, then members

Registers a version: `nmembers` ObjVersionMember records follow, one per
chunk copy that holds it. `OBJ_REMOVE_VERSION` replies with the same records (the
copies to destroy).

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                                                                       |
     |                                    uint8_t id[16]                                     |
     |                                                                                       |
  8  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 16  |                                                                                       |
     |                                uint8_t version_id[16]                                |
     |                                                                                       |
 24  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
 32  |                                                                                       |
     |                              uint8_t idempotency_key[16]                              |
     |                                                                                       |
 40  |                                                                                       |
     |                                                                                       |
     +-------------------------------------------+-------------------------------------------+
 48  |             uint32_t nmembers             |
     |                                           |
     +-------------------------------------------+
```

ObjVersionMember — 24 bytes:

```text
     +0         +1         +2         +3         +4         +5         +6         +7
     +---------------------------------------------------------------------------------------+
  0  |                                uint64_t logical_index                                 |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
  8  |                                                                                       |
     |                                  uint8_t ost_id[16]                                   |
     |                                                                                       |
 16  |                                                                                       |
     |                                                                                       |
     +---------------------------------------------------------------------------------------+
```
