# Known limitations

What Rawstor does not do yet, and the risks it accepts for now. Each item
links to the document that explains it. A feature marked ❌ in a document's
status table is not implemented; this page collects the ones that matter when
deciding how to deploy.

## Data safety and mirroring

- **One writer process per object.** An object is a virtual disk used by one
  client process at a time (one VM through `rawstor-vhost` or `rawstor-vduse`).
  Several writer processes (multi-attach) are not supported and nothing
  refuses them. Inside one process the object may be open several times, for
  example by every virtqueue of a multiqueue device; those opens act as one
  writer. See [Mirroring](mirroring.md#model-and-assumptions) and
  [Multi-attach](multiattach.md).
- **The degrade-barrier window.** Without a durable data write per request,
  there is a short window between an acknowledged write and the durable
  exclusion of a failed member. If an OST crash that loses acknowledged writes
  is followed by a client crash inside that window, the next heal can take the
  member that lost data as the reference and overwrite the only copy that still
  held them. Closing it needs synchronous durable writes or an OST start
  identity. See [Mirroring](mirroring.md#known-limitation-the-degrade-barrier-window).
- **No persistent write-intent bitmap.** A resync interrupted by a crash
  restarts from scratch, and an unclean client shutdown costs a full heal of
  the object.
- **No stored checksums or scrub.** The transport hash does not catch silent
  on-disk corruption (bit rot): the server hashes data that is already
  corrupted. See [Mirroring](mirroring.md#failure-cases).
- **Overlapping writes in flight at once** leave those blocks unspecified, and
  the copies may differ there. It is the contract a single disk gives racing
  `O_DIRECT` writes; a guest's page cache never issues such writes.
- **A witness only with an even number of data copies.** Odd mirror counts
  need none and do not get one. See [Witness members](witness.md).

## Metadata server

- **A single instance, no replication.** The chunk map lives in one SQLite
  database owned by one `rawstor-mds` per cluster. It is not in the data path,
  and the map can be rebuilt from the OSTs with `rawstor-mds --reconstruct`.
  See [MDS design](mds.md#mds-server-v1-single-instance).
- **A static topology.** OSTs are listed in a file and reloaded on `SIGHUP`;
  there is no dynamic membership service. A reload that drops an OST still
  holding chunks is refused. Existing chunks are never moved when an OST is
  added.
- **Grow-only resize.** `rawstor object resize` can grow an object by whole chunks;
  shrinking is refused.
- **No authentication or capabilities.** Anyone who can reach an MDS or OST port
  can use it. Run them on a trusted network.
- **No protocol version or feature negotiation** in the wire protocol yet; see
  [Protocol](protocol.md).
- **Free space is reported by sampling.** `rawstor info mds://` shows the last
  probe of every OST. A create, grow or remove makes the MDS probe the OSTs it
  touched after `RAWSTOR_MDS_OPTS_INFO_REFRESH_DELAY`, but a client that is
  still working on the OSTs by then may be seen half done until the next
  probe. See [Configuration](configuration.md).
- **Host names are resolved to IPv4 only.** A host name in a location,
  topology file or listen address is looked up (blocking) when connecting or
  binding, and only its IPv4 address is used. A client-local location such as
  `file://` only makes sense on a single host.

## Versions

- **The barrier is held by the servers.** A version of an object is one
  consistent point in time only if every write goes through a `rawstor-ost`.
  A zvol written directly bypasses the barrier; serve it through `rawstor-ost`
  or stop the writers first. See [MDS design](mds.md).
- **Very large objects can outlast the lease.** The barrier lease is capped
  at 10 minutes and is not renewed in flight; an object whose copy-on-write
  takes longer fails with `-ESTALE` and its version is removed.
- **No thin LVM backend.** `lvm://` versions are classic snapshots.
- **Confirming a version** after the fact is not implemented, and a
  reconstruct of the chunk map skips version records.

## Front ends

- **`rawstor-vhost` serves one front-end connection per process.** It exits
  when QEMU disconnects or on a setup error, so pair it with `reconnect=1` and
  a supervisor (the shipped `rawstor-vhost@` unit is one). See
  [rawstor-vhost](vhost.md#notes).
- **`rawstor-vduse` has no dirty page logging,** so a VM driven through it
  cannot be live-migrated; `rawstor-vhost` can.
- **`rawstor-vduse` and write-cache control.** VDUSE has no writable config
  space and the kernel rejects `VIRTIO_BLK_F_CONFIG_WCE`, so the guest cannot
  switch the cache mode at run time. See [rawstor-vduse](vduse.md#supported-virtio-blk-features).
- **A restarted `rawstor-vduse` must be back within the kernel's VDUSE message
  timeout** (30 s by default, `/sys/class/vduse/UUID/msg_timeout`), and must
  keep its `--num-queues`.

## Platform

- **Linux with `io_uring`.** The default I/O engine needs a kernel that allows
  it (`kernel.io_uring_disabled`); a build `--without-liburing` uses a `poll()`
  fallback. Some Ubuntu kernels fail to register provided buffer rings; see
  [Troubleshooting](troubleshooting.md).
- **VDUSE is Linux-only** and needs the `vduse` kernel module and
  `CAP_NET_ADMIN` to attach the device to the vDPA bus.
