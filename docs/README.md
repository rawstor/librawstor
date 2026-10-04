# Rawstor documentation

## Status

Legend: ✅ implemented · 🟡 partial · ❌ not implemented yet. Checked against
the code on 2026-10-04.

| Doc | What it covers | Status |
|---|---|---|
| [Concepts](concepts.md) | Location / Target / Object / Chunk / Slot / Snapshot | ✅ mostly implemented; ❌ data-locality policy, ❌ LVM snapshots |
| [Architecture](architecture.md) | Early high-level draft (OST, MDS, MGS, client) | 🟡 OST, MDS, client library and block clients exist; ❌ MGS, S3 gateway, compression/encryption |
| [Protocol](protocol.md) | Wire protocol, commands, frame layouts | ✅ every listed command is implemented by its server role and by the client |
| [MDS design](mds.md) | Placement, chunking, snapshots, witness | ✅ stages 1–2 (chunking, snapshots) minus the epoch-fence; ❌ stage 3 (witness) and v2+ |
| [Mirroring](mirroring.md) | N-way mirror failure model and recovery | ✅ stages 1–3 (metadata, quorum, degrade, resync); ❌ force-open, stage 4 (v2+) |

- [Concepts](concepts.md) -- Location and Target: the addressing model every other doc builds on.
- [Architecture](architecture.md) -- high-level component overview (OST, MDS, MGS, client library).
- [Protocol](protocol.md) -- the wire protocol `rawstor-ost` and `rawstor-mds` speak: commands and frame layouts.
- [MDS design](mds.md) -- the metadata storage target: placement, chunk allocation, snapshots.
- [Mirroring](mirroring.md) -- N-way mirror failure model and recovery.
