# Witness members

A witness stores consistency metadata and supplies a safe degraded-open vote
for an even number of data copies; it never stores or serves their data. Declare it explicitly:

```sh
rawstor object create --size=1G --mirrors=2 \
  'ost://10.0.0.11:9090,ost://10.0.0.12:9090,ost://10.0.0.13:9091'
```

One witness is supported only with an even number of data copies. Both
open and write quorums count it after a synchronous configuration barrier:
1 of 2 data copies plus witness, or 2 of 4 plus witness, can continue.
`--mirrors` counts data copies. Keep the complete target and member order.
A witness is addressed by its physical location: `ost://` (also for the one an MDS hosts, at the MDS's own port), `file://`, `lvm://` or `zfs://`. An `mds://` URI names a logical object, not a witness.
With one more location than `--mirrors`, the last is the witness; the stored
`META.member_role` identifies its type at subsequent opens. MDS stores its witness records durably in SQLite.
A chunk the MDS places with an even mirror count gets a witness automatically ([Automatic witness placement](mds.md#automatic-witness-placement)); declare one explicitly only for plain `ost://` objects and similar targets.
`rawstor object slots` reports its member role and record state. See
[Witness](mds.md#witness) for voting and failure rules. Interprocess
mirror coordination is multiattach stage 2 and is not implemented here.
