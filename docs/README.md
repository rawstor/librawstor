# Rawstor documentation

- [Concepts](concepts.md) -- Location and Target: the addressing model every other doc builds on.
- [Architecture](architecture.md) -- high-level component overview (OST, MDS, MGS, client library).
- [Protocol](protocol.md) -- the wire protocol `rawstor-ost` and `rawstor-mds` speak: commands and frame layouts.
- [MDS design](mds.md) -- the metadata storage target: placement, chunk allocation, versions.
- [Mirroring](mirroring.md) -- N-way mirror failure model and recovery.
- [Multi-attach](multiattach.md) -- several writers of one mirrored object, without a primary.
