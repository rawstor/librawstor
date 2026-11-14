# Rawstor documentation

- [Quick start](quickstart.md) -- a mirrored VM disk from packages, every service run by systemd.
- [Concepts](concepts.md) -- Location and Target: the addressing model every other doc builds on.
- [Architecture](architecture.md) -- high-level component overview (OST, MDS, MGS, client library).

Services:

- [rawstor-ost](ost.md), [rawstor-mds](mds-server.md), [rawstor-vhost](vhost.md), [rawstor-vduse](vduse.md) -- command-line options, systemd instances and packaging of each service.
- [Configuration](configuration.md) -- environment variables of the client and servers.
- [Witness members](witness.md) -- a metadata-only vote for an even number of data copies.

Design:

- [Protocol](protocol.md) -- the wire protocol `rawstor-ost` and `rawstor-mds` speak: commands and frame layouts.
- [MDS design](mds.md) -- the metadata storage target: placement, chunk allocation, versions.
- [Tenants](tenants.md) -- namespaces of objects: addressing, wire protocol, storage layout, the MDS registry.
- [Security](security.md) -- planned authentication, authorization, TLS, tenants and at-rest encryption, in stages.
- [Mirroring](mirroring.md) -- N-way mirror failure model and recovery.
- [CASPaxos](caspaxos.md) -- a replicated register without a leader: acceptors and coroutine-based proposers.
- [Multi-attach](multiattach.md) -- several writer processes of one mirrored object, in stages.

Development:

- [Building from source](building.md) -- build and run every service by hand on one machine.

Project:

- [Known limitations](limitations.md) -- what is not implemented yet and the risks accepted for now.
- [Troubleshooting](troubleshooting.md) -- `io_uring` problems and how to tell them apart.
- [Authors](authors.md) -- who wrote Rawstor.
