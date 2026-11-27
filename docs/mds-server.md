# rawstor-mds – Metadata Server

`rawstor-mds` is the metadata server behind `mds://<host>:<port>/<uuid>`
targets: a logical object split into fixed-size chunks, each independently
placed (and optionally mirrored) across the OSTs registered with it, opened/
read/written through the same `rawstor_target_*()`/`rawstor` CLI surface
as a plain object (see [MDS design](mds.md)). A single instance owns the explicit
chunk map and the topology of its own cluster (SQLite, WAL journal); it is not
in the data path -- `rawstor_target_open()` talks to the placed OSTs directly
once it has resolved an object's own chunk map.

The MDS keeps no OST list of its own: every OST started with `--mds` pointing
at it registers itself, with the location the clients reach it at, its failure
domain and its weight, and keeps registering every heartbeat interval (see
[OST registration](mds.md#ost-registration)). New chunks are placed only on the
OSTs that have registered within the last three intervals.

## Usage

`rawstor-mds [options] -b ADDR -d URI`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `--insecure` | Run without TLS: plaintext, and no peer is authenticated. Without it the process needs [TLS settings](configuration.md#tls) and refuses to start without them. |
| `-b, --bind ADDR` | Bind address in `<ip>[:<port>]` format (e.g., `127.0.0.1:7776`); the port defaults to 7776. |
| `-d, --db URI` | Connection string of the database holding the chunk map and the topology, created if missing; its scheme names the database. Only SQLite is supported: `sqlite:///path/to/file`. |
| `--queue-size SIZE` | RawIO queue (`io_uring`) depth. Default: `4096`. |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket and sharing one database (default: `4`). |
| `-r, --reconstruct` | Rebuild the chunk map from a LIST+META scan of the OSTs -- for recovering from a lost or corrupted database. The MDS waits a lease (three heartbeat intervals) for the OSTs to register and scans the ones that have, answering only registrations meanwhile; an OST of its topology that did not register is logged (see [Reconstruct / DR](mds.md#reconstruct--dr)). |
| `--advertise LOCATION` | Host a witness: the location the clients reach it at, `ost://<this host>:<port>` (see [Automatic witness placement](mds.md#automatic-witness-placement)). Empty or absent: no witness. |
| `--domain-path PATH` | The witness's failure domain, `[[[dc/]row/]rack/]server`; required with `--advertise`. |
| `--weight N` | The witness's share of new witnesses (default: `100`). |
| `--id UUID` | The MDS's id, which its witness goes by: required with `--advertise` and `--insecure`; with TLS, that of its certificate, which `--id` must then match. |

## Examples

Serve two OSTs, which register themselves:
```bash
rawstor-mds --insecure -b 0.0.0.0:7776 -d sqlite:///var/lib/rawstor/mds/mds.db
# on host1 and host2:
rawstor-ost --insecure -b 0.0.0.0:7777 --id ${OST_ID} --mds mds://mds:7776 \
    --advertise ost://$(hostname):7777 --domain-path dc1/row1/rack1/$(hostname) \
    file:///var/lib/rawstor/ost
```

Create and grow an `mds://` object:
```bash
rawstor object create -t mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=1G --chunk-size=256M --mirrors=1
rawstor object resize mds://127.0.0.1:7776/018f4e2a-2000-7000-8000-000000000001 --size=2G
```

Add an OST: start it with `--mds`. Its first registration enters it in the
topology (`OST ... registered at ... in ...` in the MDS's log); new chunks may
then be placed on it, existing ones stay where they are. Remove one: stop it.
It registers as leaving on its way out, is unavailable at once, and its entry
goes once nothing is placed on it.

## Packaging and systemd instances

`rawstor-mds` ships in its own `rawstor-mds` deb/rpm package (needs
`sqlite3`; skip building it with `--without-sqlite3`), along with the
`rawstor-mds@.service` systemd template. One instance serves one cluster,
named after the cluster's id and configured by `/etc/rawstor/mds/<uuid>.conf`.
Installing the package starts nothing; an instance without its config refuses
to start.

The config is an environment file (`KEY=VALUE` lines):

| Key | Default | Description |
|-----|---------|-------------|
| `BIND_ADDR` | — (required) | `<ip>:<port>` to listen on, unique per host. |
| `DB_URI` | `sqlite:///var/lib/rawstor/mds/<uuid>/mds.db` | `--db`; the directory of an SQLite file must be writable by `rawstor`. |
| `QUEUE_SIZE` | `4096` | `--queue-size`. |
| `WORKERS` | `4` | `--workers`. |
| `ADVERTISE`, `DOMAIN_PATH`, `WEIGHT` | empty, empty, `100` | `--advertise`, `--domain-path`, `--weight`: the witness the instance hosts; none while `ADVERTISE` is empty. |
| `RAWSTOR_TLS_*` | | TLS settings, see [Configuration](configuration.md#tls). |
| `RAWSTOR_MDS_OPTS_*`, `RAWSTOR_OPTS_*` | | Tuning knobs, see [Configuration](configuration.md). |

The instance runs as the `rawstor` user under `ProtectSystem=strict`;
`/var/lib/rawstor/mds/<uuid>` (`StateDirectory=`) is created on start.
A database anywhere else needs a drop-in (`ReadWritePaths=`), as for
`rawstor-ost`. `systemctl reload` reads the TLS certificate, key and CAs again.

Two clusters on one host:

```bash
# Each instance has its own certificate, for spiffe://<trust domain>/mds/<mds id>:
# /etc/rawstor/tls/<cluster>.crt and <cluster>.key, see Configuration for TLS.
tls() {
    printf 'RAWSTOR_TLS_TRUST_DOMAIN=cluster.example\nRAWSTOR_TLS_CERT=/etc/rawstor/tls/%s.crt\nRAWSTOR_TLS_KEY=/etc/rawstor/tls/%s.key\nRAWSTOR_TLS_CA=/etc/rawstor/tls/ca.crt\n' $1 $1
}
(echo BIND_ADDR=0.0.0.0:7776; tls ${CLUSTER1}) | sudo tee /etc/rawstor/mds/${CLUSTER1}.conf
(echo BIND_ADDR=0.0.0.0:7786; tls ${CLUSTER2}) | sudo tee /etc/rawstor/mds/${CLUSTER2}.conf
sudo systemctl enable --now rawstor-mds@${CLUSTER1} rawstor-mds@${CLUSTER2}

rawstor location info mds://127.0.0.1:7776   # serving? (with RAWSTOR_TLS_* in the environment)
# point the OSTs of cluster 1 at it (MDS=mds://<this host>:7776, see rawstor-ost), then
journalctl -u rawstor-mds@${CLUSTER1} | grep registered   # registered?
rawstor location list mds://127.0.0.1:7776   # the locations the MDS serves
```

Removing an instance (`systemctl disable --now`, then deleting its config)
keeps its database; a package upgrade restarts the running instances and
removing the package stops them, leaving configs and databases in place.
