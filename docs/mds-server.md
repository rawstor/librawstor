# rawstor-mds – Metadata Server

`rawstor-mds` is the metadata server behind `mds://<host>:<port>/<uuid>`
targets: a logical object split into fixed-size chunks, each independently
placed (and optionally mirrored) across a static OST topology, opened/
read/written through the same `rawstor_target_*()`/`rawstor` CLI surface
as a plain object (see [MDS design](mds.md)). A single instance owns the explicit
chunk map (SQLite, WAL journal) and the static topology config for its own
cluster; it is not in the data path -- `rawstor_target_open()` talks to
the placed OSTs directly once it has resolved an object's own chunk map.

## Usage

`rawstor-mds [options] -b ADDR -d DBPATH -t TOPOLOGY`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `-b, --bind ADDR` | Bind address in `<ip>[:<port>]` format (e.g., `127.0.0.1:7776`); the port defaults to 7776. |
| `-d, --db PATH` | SQLite database file holding the chunk map (created if missing). |
| `-t, --topology PATH` | Static topology config file: one `<uuid> <location> <weight> <role> [[[<dc>/]<row>/]<rack>/]<server>` line per OST (required role: `data`, `witness` or both comma-separated; failure domains from the root down; only `<server>` is required), `<location>` being a single location URI (`ost://host:port`; a client-local one such as `file://` only makes sense on a single host; each `rawstor-ost` serves one backend location) (see [MDS design](mds.md)). |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth. Default: `4096`. |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket and sharing one database (default: `4`). |
| `-r, --reconstruct` | Rebuild the chunk map from a LIST+META scan of every OST in the topology before serving -- for recovering from a lost or corrupted database. |

## Examples

Serve a topology of two OSTs:
```bash
cat > topology.conf <<EOF
018f4e2a-1000-7000-8000-000000000001 ost://host1:7777 100 data,witness dc1/row1/rack1/host1
018f4e2a-1000-7000-8000-000000000002 ost://host2:7777 100 data,witness dc1/row1/rack1/host2
EOF
rawstor-mds -b 0.0.0.0:7776 -d /var/lib/rawstor/mds/mds.db -t topology.conf
```

Create and grow an `mds://` object:
```bash
rawstor object create -t mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=1G --chunk-size=256M --mirrors=1
rawstor object resize mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=2G
```

Add an OST: append its line to `topology.conf` and send `SIGHUP`
(`systemctl reload rawstor-mds@<uuid>`). New chunks may then be placed on
it; existing ones stay where they are. Client connections are kept. A
topology that doesn't parse, or drops an OST still holding chunks, is
refused: on reload the current one is kept and the reason logged
(`Topology reload from ... failed, keeping the current one: ...`), at
startup the MDS doesn't start.

## Packaging and systemd instances

`rawstor-mds` ships in its own `rawstor-mds` deb/rpm package (needs
`sqlite3`; skip building it with `--without-sqlite3`), along with the
`rawstor-mds@.service` systemd template and a commented topology example,
`/usr/share/doc/rawstor-mds/topology.conf`. One instance serves one
cluster, named after the cluster's id and configured by
`/etc/rawstor/mds/<uuid>.conf`. Installing the package starts nothing; an
instance without its config refuses to start.

The config is an environment file (`KEY=VALUE` lines):

| Key | Default | Description |
|-----|---------|-------------|
| `BIND_ADDR` | — (required) | `<ip>:<port>` to listen on, unique per host. |
| `TOPOLOGY_PATH` | `/etc/rawstor/mds/<uuid>.topology` | Topology file; must exist (may be empty) and be readable by `rawstor`. |
| `DB_PATH` | `/var/lib/rawstor/mds/<uuid>/mds.db` | Database; its directory must be writable by `rawstor`. |
| `QUEUE_SIZE` | `4096` | `--queue-size`. |
| `WORKERS` | `4` | `--workers`. |
| `RAWSTOR_MDS_OPTS_*`, `RAWSTOR_OPTS_*` | | Tuning knobs, see [Configuration](configuration.md). |

The instance runs as the `rawstor` user under `ProtectSystem=strict`;
`/var/lib/rawstor/mds/<uuid>` (`StateDirectory=`) is created on start.
A database anywhere else needs a drop-in (`ReadWritePaths=`), as for
`rawstor-ost`.

Two clusters on one host:

```bash
for C in ${CLUSTER1} ${CLUSTER2}; do
    sudo cp my-${C}.topology /etc/rawstor/mds/${C}.topology
done
echo "BIND_ADDR=0.0.0.0:7776" | sudo tee /etc/rawstor/mds/${CLUSTER1}.conf
echo "BIND_ADDR=0.0.0.0:7786" | sudo tee /etc/rawstor/mds/${CLUSTER2}.conf
sudo systemctl enable --now rawstor-mds@${CLUSTER1} rawstor-mds@${CLUSTER2}

rawstor location info mds://127.0.0.1:7776          # serving?
# edit /etc/rawstor/mds/${CLUSTER1}.topology, then
sudo systemctl reload rawstor-mds@${CLUSTER1}
journalctl -u rawstor-mds@${CLUSTER1} | grep Topology   # applied?
```

Removing an instance (`systemctl disable --now`, then deleting its config)
keeps its database; a package upgrade restarts the running instances and
removing the package stops them, leaving configs and databases in place.
