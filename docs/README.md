# Rawstor documentation

- [Concepts](concepts.md) -- Location and Target: the addressing model every other doc builds on.
- [Architecture](architecture.md) -- high-level component overview (OST, MDS, MGS, client library).
- [Protocol](protocol.md) -- the wire protocol `rawstor-ost` and `rawstor-mds` speak: commands and frame layouts.
- [MDS design](mds.md) -- the metadata storage target: placement, chunk allocation, versions.
- [Mirroring](mirroring.md) -- N-way mirror failure model and recovery.
- [CASPaxos](caspaxos.md) -- a replicated register without a leader: acceptors and coroutine-based proposers.
- [Multi-attach](multiattach.md) -- several writer processes of one mirrored object, in stages.
- [Authors](authors.md) -- who wrote Rawstor.
- [Quick start from source](quickstart.md) -- build and run every service by hand on one machine.
- [Known limitations](limitations.md) -- what is not implemented yet and the risks accepted for now.
- [Configuration](configuration.md) -- environment variables of the client and servers.
- [rawstor-ost](ost.md), [rawstor-mds](mds-server.md), [rawstor-vhost](vhost.md), [rawstor-vduse](vduse.md) -- command-line options, systemd instances and packaging of each service.
- [Witness members](witness.md) -- a metadata-only vote for an even number of data copies.
- [Troubleshooting](troubleshooting.md) -- `io_uring` problems and how to tell them apart.
