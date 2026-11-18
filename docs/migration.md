# Changing a chunk's members: mirror count, migration, drain

## Status

Legend: ✅ implemented · 🟡 partial · ❌ not implemented yet. *Stage* is this
document's own numbering (see [Implementation stages](#implementation-stages));
[MDS design](mds.md) and [Mirroring](mirroring.md) number theirs separately.

| Feature | Stage | Status | Where |
|---|---|---|---|
| Weight 0 keeps an OST out of every new placement (data and witness) | 0 | ✅ | `mds/src/placement.cpp`; no end-to-end test, not documented for operators |
| Topology refuses to drop an OST that still holds chunks or version members | — | ✅ | `mds/src/store.cpp` |
| Topology flag `decommissioned` | 0 | ❌ | — |
| List the slots and version members held by one OST | 0 | ❌ | — |
| Member roles `LEARNER`, `RETIRED`; the voter set is explicit | 1 | ❌ | [Roles and voters](#roles-and-voters) |
| Joint decision (majority of the old and of the new voters) | 1 | ❌ | [The change as a register transition](#the-change-as-a-register-transition) |
| Member list change adopted by a running writer (`-ESTALE`, re-resolve) | 1 | ❌ | [How a writer learns it](#how-a-running-writer-learns-the-new-member-list) |
| `width` of a chunk rewritten by a decision | 1 | ❌ | — |
| `place_replacement()`: placement of added slots next to existing ones | 2 | ❌ | — |
| MDS plan record, `OBJ_RECONFIGURE_*`, `joining`/`leaving` slots in `RESOLVE` | 2 | ❌ | [MDS side](#mds-side) |
| Executor and CLI: `rawstor object migrate`, `rawstor object mirrors` | 3 | ❌ | — |
| `rawstor ost drain`, `rawstor ost status`; recovery of a dead OST's slots | 4 | ❌ | — |
| Versions of a moved chunk copied to the new member | 5 | ❌ | [Versions](#versions) |
| Backend / `chunk_meta` format change by migration | 6 | ❌ | [Changing backend or format](#changing-backend-or-metadata-format) |

Four operations are wanted, and they are one mechanism:

| Operation | In terms of the mechanism |
|---|---|
| Change the number of mirrors of an object | per chunk: add and/or remove members |
| Migrate one disk (object) off an OST, to a chosen or a placed OST | per chunk: replace the member on that OST |
| Drain an OST (decommission) | migrate every slot on it, with the OST closed to new placement |
| Change the backend of a disk (`zfs://` → `lvm://`), or its metadata format | migrate to an OST that has the other backend or the newer software |

Everything below is about one primitive, `reconfigure(chunk, new members)`, and
the orchestration around it.

See also: [MDS design](mds.md), [Mirroring](mirroring.md),
[Multi-attach](multiattach.md), [CASPaxos](caspaxos.md).

## What the design builds on

- **A chunk is the unit.** Each chunk of an object has its own members and its
  own configuration register; chunks of one object may have different widths
  ([Mirroring](mirroring.md#overview)). An object-level operation is the same
  operation run on each chunk in turn, and a half-done object is a valid state.
- **The register decides, the writer is only a proposer.** Every transition of
  a chunk's configuration is a CASPaxos decision over the chunk's members; any
  writer process may propose, and the others adopt the decided value when a
  member answers `-ESTALE` ([Multi-attach](multiattach.md)). Epoch fencing
  already guarantees that no write is acknowledged against an outdated
  configuration (A3).
- **Resync is the data mover.** A member in role *syncing* receives a full
  online copy from an in-sync member, together with the duplicated client
  writes of every writer, without stopping I/O (F7,
  [Resync across processes](multiattach.md#resync-across-processes)).
- **The MDS is an index with durable placement decisions** and is not on the
  I/O path. It resolves a chunk's members once at open.
- **OST side is the durable ground truth** ([MDS principles](mds.md#principles)):
  the MDS map must be rebuildable from OST records after a disaster.

Two limits of the present model are what the design has to lift:

1. A chunk's member list is fixed for its life. `Chunk` requires the
   register's `nroles` to equal its member count, the persisted `width` is
   compared at open (F11), and a witness is the last location beyond `width`.
2. The voter count `N` is the length of the member list: a member that is
   *syncing* or *excluded* still counts in `N`. Adding a member to a live chunk
   would raise `N` before the new member can vote, and a one-copy chunk would
   freeze its writes the moment a second member is added.

## Weight 0 and draining

`weight 0` in `topology.conf` keeps an OST out of **every new placement**:
`place()` skips zero-weight OSTs before building failure domains, and the
witness candidate filter and the domain-count checks skip them too
(`mds/src/placement.cpp`; unit test
`PlacementTest.zero_weight_ost_never_populates_a_domain`). Existing slots are
untouched: the map is explicit, reads and writes go on, a `SIGHUP` reload
accepts the new weight, and only *dropping* an OST that holds chunks is refused.
Consequences worth knowing:

- Create and grow fail with the usual hard error if the remaining weighted
  OSTs cannot satisfy `width` and `failure_domain`; nothing is placed on the
  drained OST instead.
- With `stripe_width` K=1 a grown object's new chunks land on whichever OSTs
  the pinned pool now picks, so locality with the earlier chunks may be lost.
- Weight 0 says nothing about slots already there. Moving them is the job of
  [Draining an OST](#draining-an-ost).

What is still missing is a test of the whole path (create and resize against a
topology with a zero-weight OST) and the operator-facing documentation of the
meaning of `0`; both are stage 0. [MDS design](mds.md#epoch-fence) also
speaks of an OST marked *decommissioned* in the topology; the topology format
has no such mark yet. It is an optional trailing `decommissioned` token on the
line (trailing tokens are rejected today, so the extension breaks no existing
file), meaning: weight 0, *and* the OST is declared dead, so a decision may
leave it out and `--reconstruct` may skip it ([Dead OST](#dead-ost)).

## The change as a register transition

### Roles and voters

The register value's `roles` gain two values next to *in-sync, syncing,
excluded* (`RawstorObjectMemberRole`):

| Role | Meaning | Gets client writes | Reads | Votes (counts in `N`) |
|---|---|---|---|---|
| `LEARNER` | a member being added; is filled by resync | duplicated, like *syncing* | no | **no** |
| `RETIRED` | a member removed by a decision; fenced, awaits release | no | no | **no** |

`N`, the quorum denominator of [Mirroring](mirroring.md#quorum-excluding-split-brain-by-construction),
becomes the number of **voters**: members that are neither `LEARNER` nor
`RETIRED`. For a chunk that never changes members the voters are all members,
so nothing changes for it. The new values are unknown to today's servers
(`-EINVAL`), so servers are upgraded before clients, as for the planned
[`HEALING` role](mirroring.md#planned-the-healing-role).

A member's *kind* (`DATA` or `WITNESS`) is read from its own record
(`member_role` in `META`); the rule "the last location beyond `width` is the
witness" holds for a chunk **at rest**, and is checked again at the end of a
change. While a change runs the layout may be any mix.

### The primitive

`reconfigure(chunk, to)`, with `from` the current voter set `S`, `to` the
wanted one `S'` (for a replacement `S' = S − {A} + {B}`; for 2→3 mirrors
`S' = S − {W} + {C}`, since an odd width has no witness; for 3→2, `S' = S + {W}`):

```mermaid
sequenceDiagram
    autonumber
    participant X as executor (a writer process)
    participant M as rawstor-mds
    participant S as voters S (old)
    participant L as learners (new members)
    X->>M: OBJ_RECONFIGURE_BEGIN(plan)
    M->>M: record plan; map = old ∪ new, new slots 'joining'; map_epoch++
    X->>L: ALLOCATE (blank, kind, width of S')
    X->>S: decide: add learners, epoch++ (majority of S)
    Note over X,L: learners get duplicated client writes, resync sweep copies the rest
    X->>L: resync from an in-sync member (RESYNC writes)
    Note over X: swept: commit
    X->>S: decide: voters = S', removed members RETIRED, epoch++
    X->>L: (same decision)
    Note over X,L: joint: accepted by a majority of S and a majority of S'
    X->>S: (members of S \ S' accept it too: this fences them)
    X->>M: OBJ_RECONFIGURE_FINALIZE
    M->>M: prune 'leaving' slots, map_epoch++
    X->>S: decide: compact roles to the final member list (voters S')
    X->>S: RELEASE removed members (volumes freed)
```

1. **Begin (MDS).** The MDS stores the plan durably and publishes the **union**
   of old and new slots in `RESOLVE`, the new ones flagged `joining`. The
   invariant for the whole change: **the MDS map is always a superset of the
   members the register names**; the register is never ahead of the MDS.
2. **Add learners.** The executor allocates blank copies on the new members
   (an ordinary `ALLOCATE`, which makes a witness a minimum-size volume), then
   decides *add learners* under the old voters: an ordinary decision, a majority of `S`.
   From the epoch it moves to, every writer duplicates writes onto the learners.
3. **Fill.** The existing resync, owner lease and `RESYNC` writes copy the data
   from an in-sync source (a zero-detecting sweep, so a sparse chunk stays
   sparse on a `zfs://` or `lvm://` member). A witness learner needs no data.
4. **Commit (the one decision that matters).** Once every data learner is
   filled, the executor decides the value in which the voters are `S'`, the
   members of `S \ S'` are `RETIRED`, `resync_owner` is 0, `sync_id` moves on
   and `epoch` is raised. This **joint** decision needs a majority of `S` *and*
   a majority of `S'` to accept it, and is sent to all members of `S ∪ S'`,
   reachable retirees included. A write acknowledged by a stale writer needs
   every member that writer believes in-sync, so it has to meet either a member
   of `S'` or one of `S` that already holds the new epoch: the intersection
   argument of the register ([A3](multiattach.md#requirements)) extended over
   two voter sets. The commit is the point of no return: before it the change
   can be aborted (learners excluded, plan removed), after it only finished.
5. **Finalize.** The MDS prunes the retired slots and the `joining`/`leaving`
   flags (`map_epoch++`), and the executor decides the compaction of `roles`
   to the final member list, a decision of `S'` only. Retired members are not
   asked again.
6. **Release.** The retired members' volumes are destroyed (`RELEASE`), later
   and without hurry: a stale writer reaching one gets an error and cannot
   acknowledge a write, since it is also refused by `S'`.

**The fence is the register.** [MDS design](mds.md#migration-updateplacement-sequence)
plans a per-slot `fence` watermark of a `map_epoch` carried in every I/O frame.
The register epoch already does that job on every write
([Epoch on writes](multiattach.md#epoch-on-writes)), and step 4 asks the leaving
member to accept the new epoch, which is exactly "record the fence on the old
owner before moving the map". A one-copy chunk needs no temporary second copy
and no witness for this: with `S = {A}` and `S' = {B}` the joint decision needs
`A` and `B`, `B` was filled as a learner, and `A` is fenced by accepting it. The
fence design of `mds.md` is replaced by this one when stage 1 lands.

### How a running writer learns the new member list

A writer holds the member list it was given at open (the MDS reply expanded
into a plain target) and keeps the register value in `MirrorControl`. To follow
a change it needs the locations of members it has never heard of.

- The register value carries `map_epoch`, the generation of the MDS map that
  lists the value's members (a new field of `RawstorFrameConfig`, rewritten by
  every membership decision).
- A writer that adopts a value whose `map_epoch` is above its own, or whose
  `nroles` differs from its member count, **re-resolves** through the MDS, opens
  `Slot`s for members it lacks, and closes those that left the map after
  finalize. Until then it does not acknowledge writes: it is exactly as
  blocked as a writer that has just been refused `-ESTALE`.
- Because the MDS map is a superset of the register's members at every moment
  (step 1), a re-resolve never lacks a member the value names. It may still see
  more members than the value: a `joining` slot with role `LEARNER` is a
  non-voting duplicate target, and a `leaving` slot with role `RETIRED` is a
  fenced member to be ignored; the roles come from the register, the locations
  from the map.
- A fresh open resolves the union map and reads the members' records as usual.
  An opener sees the roles in the records and needs no knowledge that a change
  is under way.
- Retaining the MDS location for the life of a writer is new: a plain
  (non-`mds://`) target has no resolver and cannot be reconfigured, which is
  right, since its members are the user's list.
- A writer that cannot reach the MDS while a change completes freezes writes
  (`EIO`) until it can. Changes are operator-started and rare; this is accepted.

### Failure cases

| Failure | Result |
|---|---|
| Executor dies before the commit | The learners' resync owner stops renewing; after the lease any writer excludes them. The plan stays in the MDS; `rawstor` resumes it (the learners are already blank-or-partial: the resync restarts from scratch, F8) or aborts it |
| Executor dies after the commit, before finalize | The register is authoritative: the plan is rolled forward by any executor that finds it (the register has `S'` as voters). Writers already run on `S'` |
| MDS unreachable during the change | Steps 1 and 5 wait; no step in between needs it (the writers do not unless they adopt a new `map_epoch`). A writer that has to re-resolve freezes until the MDS is back |
| A learner dies while filling | An ordinary member failure: excluded, resync restarts when it returns, or the plan is aborted. The old voters never stopped serving |
| A member of `S` dies during the change | The register decides under the voters as usual; the commit then needs a majority of `S` without it. With `S = {A}` (one copy) the loss of `A` is the loss of the data, a change or not |
| Source of the resync dies | As in [multi-attach](multiattach.md#servers): the owner aborts, another in-sync member is the source, else the change aborts |
| Two plans for one chunk | The MDS refuses the second (`-EBUSY`): one plan record per chunk |
| A stale writer from before the commit | Refused `-ESTALE` by every member of `S'` and by every retiree that accepted the commit; cannot acknowledge. A retiree that was down and returns is a stale copy by `sync_id` ancestry |
| A retired member that comes back and is opened by hand | Its record is `RETIRED` at an old epoch: an ordinary stale copy, caught at open by the comparison rules; its volume is garbage to collect |

## Operations

### Changing the number of mirrors

`rawstor object mirrors TARGET N` sets the object's `width` to `N`:

1. The descriptor's policy `width` is updated first, so that a concurrent resize
   places new chunks with the new width.
2. Each existing chunk is reconfigured, one chunk (or a bounded number) at a
   time:
   - **Grow** by `k`: `place_replacement()` picks `k` more OSTs (and a witness
     if the new width is even and the chunk has none), weighted HRW over OSTs of
     weight > 0 and in **failure domains different from every kept member**.
     If that is impossible the operation fails for that chunk, and is reported;
     it is never relaxed silently ([MDS placement](mds.md#placement-function)).
   - **Shrink** by `k`: the executor chooses which members leave. By default
     the members on the OSTs with the least free space or weight-0 OSTs first,
     never the only in-sync source, and the witness is added or dropped to
     match the parity of the new width. The operator may name the OSTs.
3. The chunk's `width` in every member's record is rewritten by the commit.

Width parity moves the witness: 2→3 retires the witness and adds a data copy in
one change (voters `{A,B,W}` → `{A,B,C}`), 3→2 adds one (`{A,B,C}` → `{A,B,W}`),
1→2 adds a copy and a witness, 2→1 removes both. The joint rule keeps every
step safe: no state exists in which the quorum is defined over a layout that
was not one of the two sets.

### Migrating a disk

`rawstor object migrate TARGET --from OST [--to OST]` replaces, in every chunk
of the object that has a slot on `OST`, that slot by one on another OST:

- the destination is `--to`, or placed by `place_replacement()` as above;
- the replacement changes one voter: `S' = S − {A} + {B}`; a chunk with no slot
  on `OST` is skipped; `--chunk OFFSET` limits it to one chunk;
- an explicit `--to` that would put two members of a chunk into one failure
  domain is refused unless the operator says `--allow-shared-domain`.

A migrating object stays open and writable; the VM is not stopped and no writer
is asked to do anything but follow the register.

### Draining an OST

```
1. weight 0 (or `decommissioned`) in topology.conf, SIGHUP          no new placement
2. rawstor ost drain OST_ID                                         each slot on it:
                                                                       migrate, one plan per chunk,
                                                                       bounded parallelism, rate limit
3. rawstor ost status OST_ID  -> slots left, version members left   done at 0 and 0
4. remove the OST from topology.conf, SIGHUP                        accepted: nothing refers to it
```

Step 2 is a loop over the MDS's index of slots by OST (stage 0), each chunk a
`reconfigure` as above; it is resumable and can be stopped and started. It runs
while the VMs run. A chunk with versions is refused until stage 5 ([Versions](#versions)).

### Dead OST

The same primitive covers recovery, `updatePlacement` of
[the MDS API](mds.md#mds-api). When an OST is lost and declared `decommissioned`,
each chunk that had a slot on it is reconfigured with that member simply left
out of `S'` (it cannot be asked and does not need to be: a majority of the
remaining voters fences it). The source of the new copy is a surviving
in-sync member. A chunk whose survivors are not a voter majority stays degraded
and is reported, as in [MDS placement](mds.md#placement-function); a one-copy
chunk on a dead OST has no source and is a data loss that no mechanism repairs.

### Changing backend or metadata format

The backend of a copy is a property of the OST that serves it: an `ost://`
location in the topology is backed by `zfs://`, `lvm://` or `file://`
(*one copy per server*, [Mirroring](mirroring.md#one-copy-per-server)).
Moving a chunk from a `zfs://` OST to an `lvm://` one is therefore an ordinary
migration to an OST with another backend. No backend-specific mover exists;
the logical size in `META` (not the physical allocation) is what members
compare, so extent and volblocksize rounding do not matter (F11).

The same goes for the `chunk_meta` format: a migration `ALLOCATE`s the new
member on an OST running the newer software, which writes its record in the
newest format, and the register value is carried over by the decisions. There
is no in-place conversion tool. This needs two things from elsewhere:

- OSTs are upgraded before clients (as for any new role or opcode), and a
  chunk may hold members at different format versions while a change runs;
- the protocol version and feature bits of `SET_OBJECT`, which
  [MDS design](mds.md#compatibility-stance) names as not implemented, once
  there is a live install to protect.

## Versions

Versions of a chunk live as native snapshots on the members that held it
([Versions](mds.md#versions-stage-2)), `versions[version_id].members` naming
those OSTs. A version cannot follow the live volume to another OST for free:
a `zfs` snapshot cannot be moved to an `lvm` snapshot chain. So:

- **Stage 2–4: refuse.** A chunk with any version is not reconfigured that
  removes a member holding one (`-EBUSY`), unless the operator removes the
  versions first. Adding a mirror is allowed: the new member holds the live
  chunk only, and the version records keep their members, as a degraded
  object's versions already may ([Versions](mds.md#versions-stage-2)).
- **Stage 5: copy.** Versions are immutable, so copying them is safe and needs
  no barrier: oldest to newest, the new member gets the version's content as
  its live volume (read through `SET_OBJECT(id, version_id)`), takes a native
  snapshot named `s<version_id>`, and the next version follows. Each version is a
  full sparse-aware copy (no portable delta between backends), the member is
  added to `versions[version_id].members`, and only then may the old
  member be released. A draining OST stays blocked on a chunk until its
  versions are copied or removed.

## MDS side

Stage 2 adds, in the MDS database and protocol:

- a `reconfigurations` table, one row per chunk in flight: the object, the chunk
  index, `from` and `to` slot lists, the phase (`begun`, `committed`,
  `finalized`), the executor's `idempotency_key`; rows are written in the same
  transaction as the map change, like `applied_mutations`;
- `OBJ_RECONFIGURE_BEGIN` (places the new slots, writes the plan, publishes the
  union map), `OBJ_RECONFIGURE_FINALIZE` (prunes, `map_epoch++`),
  `OBJ_RECONFIGURE_ABORT` (before the commit only). All three are idempotent
  mutations ([Idempotent mutations](mds.md#idempotent-mutations)). Where in
  `RESOLVE`'s reply the `joining`/`leaving` flag goes is a wire change in
  `RawstorFrameResolve*` and `docs/protocol.md`;
- `place_replacement(topology, id, index, kept_slots, policy, kind)` next to
  `place_chunk()` in `mds/src/placement.cpp`: the same hierarchical HRW with
  the kept members' domains excluded;
- a query *slots and version members of OST X*, paged, for drain and status;
- the resume path: a plan found at MDS start or by an executor is judged by the
  register, not by the MDS: committed there means rolled forward.

`--reconstruct` rebuilds the map from OST records ([Reconstruct](mds.md#reconstruct-dr)).
A copy whose own role is `LEARNER` is not registered (it is incomplete), a
`RETIRED` one is garbage to collect, and a chunk left mid-change is
reconstructed from its voters. For the order of members, the records must carry
their `slot_index` as `chunk_meta` already specifies.

## Executor

The mover is a client process that opens the chunk as one more writer: it needs
the proposer, the resync engine and the MDS access that every writer has, and
multi-attach stage 2 lets it run next to the VM's own process. It is a
subcommand of `rawstor` (`object migrate`, `object mirrors`, `ost drain`) first;
a long-running balancer daemon over the same code is a later consumer and not a
different mechanism.

- one chunk at a time per object by default, `--parallel N` across chunks,
  `--rate` for the sweep so foreground I/O is not starved;
- every step is idempotent and re-entrant: a killed executor is restarted by
  the same command, which finds the plan in the MDS and the value in the register;
- progress and errors are per chunk and are printed by `rawstor object chunks`
  (a state column: `joining`, `committed`, `done`).

## Tests

Following the repository's rule that tests exercise behavior through existing
interfaces, each stage has its test at the layer it adds:

- stage 1: `Chunk` with a test resolver, a writer process running while the
  voter set changes (replacement of one copy, 1→2, 2→3 with the witness
  swap, 3→2), crash of the executor at each phase, stale writer after the
  commit gets `-ESTALE`; the ASAN stress shape used for resync;
- stage 2: placement (`place_replacement` never reuses a kept domain), store
  (plan rows, idempotent replay, one plan per chunk), reconstruct of a chunk
  mid-change;
- stage 3: end-to-end with `rawstor-vhost`-like writes during `migrate` and
  `mirrors`;
- stage 4: drain of an OST in a multi-OST test topology with weight 0.

## Implementation stages

0. **Preparation.** Test and document `weight 0`; the `decommissioned` token;
   the MDS query of slots and version members by OST.
1. **Membership in the register.** Roles `LEARNER`/`RETIRED`, explicit voters,
   joint decision, `map_epoch` in the value, writer adoption with re-resolve,
   `width` rewrite, compaction. A library-level API on `Chunk`, no MDS yet.
   Servers first (new role values).
2. **MDS plans.** `place_replacement`, plan table, `OBJ_RECONFIGURE_*`, union
   `RESOLVE`, reconstruct rules, the `-EBUSY` rule for versions.
3. **Executor and CLI.** `rawstor object migrate`, `rawstor object mirrors`,
   resume, rate limit, per-chunk status.
4. **Drain and recovery.** `rawstor ost drain` / `status`, removal from the
   topology, recovery of a `decommissioned` OST's slots.
5. **Versions.** Copy to the new member, then drain no longer blocks on them.
6. **Backend and format.** Cross-backend verification of migration
   (zfs↔lvm↔file), mixed format versions in one chunk, the protocol version
   handshake.

Stage 1 is the work: after it a chunk can change members under live writers;
the rest is policy, bookkeeping and tools.

## Open questions

- **Re-resolve versus members in the register.** The design re-resolves from
  the MDS. Writing member locations into the register value would remove the
  MDS from the adoption path, at the price of a larger value and the topology
  living in the OST records; rejected for now because changes are rare and the
  MDS is already needed to start them.
- **Layout rule.** Today the witness is "the last location beyond `width`".
  Whether the layout check at rest should stay positional, or read member kinds
  from the records, is to be settled with the stage 1 code.
- **Many chunks, one plan.** A plan per chunk is simple and resumable; for an
  object of thousands of chunks a coalesced plan record may be needed.
- **Automatic rebalancing** by weight is a consumer of `migrate`, not part of
  this design.
