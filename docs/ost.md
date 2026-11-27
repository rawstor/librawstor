# rawstor-ost – OST Protocol Server

`rawstor-ost` implements the **OST protocol** (see [Protocol](protocol.md)), handling network connections and providing access to data stored in one backend **location** (as defined in the [Concepts](concepts.md) documentation).

- `file://` scheme → serves data directly from the local filesystem.
- `ost://` scheme → acts as a proxy to an underlying OST backend.
- Comma‑separated list → supports mirroring or data locality.

## Usage

`rawstor-ost [-h] [--insecure] -b ADDR LOCATION`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `--insecure` | Run without TLS: plaintext, and no peer is authenticated. Without it the process needs [TLS settings](configuration.md#tls) and refuses to start without them. |
| `LOCATION` | Comma‑separated list of backend locations (e.g., `file:///path`, `ost://host:port`). |
| `-b, --bind ADDR` | Bind address in `<ip>[:<port>]` format (e.g., `127.0.0.1:7777`); the port defaults to 7777. |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket (default: `12`). |
| `--meta-cache-ttl MS` | How long, in milliseconds, the member records of a `file://`, `lvm://` or `zfs://` store stay in memory ([Member record cache](#member-record-cache)); `0` reads the store every time (default: `60000`). |
| `--mds LOCATION` | Register with the MDS of the cluster, `mds://host:port` ([Registration with an MDS](#registration-with-an-mds)). Empty or absent: no registration. |
| `--id UUID` | The OST's id; required with `--mds`. With TLS it must be the id of the OST's certificate, or the OST does not start. |
| `--advertise LOCATION` | The location the clients reach the store at, normally `ost://<this host>:<port>`; required with `--mds`. |
| `--domain-path PATH` | The OST's failure domain, `[[[dc/]row/]rack/]server`; required with `--mds`. |
| `--weight N` | The OST's share of new chunks, e.g. its capacity in GiB (default: `100`). |

## Examples

Serve local directory:
```bash
rawstor-ost -b 0.0.0.0:7777 file:///var/rawstor/data
```

Proxy to remote OST:
```bash
rawstor-ost -b 0.0.0.0:7777 ost://192.168.1.100:7777
```

Data locality (local cache + proxy):
```bash
rawstor-ost -b 0.0.0.0:7777 file:///var/rawstor/data,ost://remote:7777
```

Mirroring between two OST backends:
```bash
rawstor-ost -b 0.0.0.0:7777 ost://left:7777,ost://right:7777
```

## Member record cache

Every client that has a mirrored object open reads the record of each of its
chunks (`META`: state, configuration, ballots, owner) every
`mirror_probe_interval`, and the OST reads it for the authorization of most
requests. On `lvm://` a read is an `lvs`, on `zfs://` a `zfs get`, on `file://`
a file read. An OST that serves a `file://`, `lvm://` or `zfs://` store keeps
the records it has read in memory for `--meta-cache-ttl`, up to 16384 of them,
the least recently used first out.

A record is kept only as the store holds it: the number of writers is the
sessions open on the OST and is added on every answer. Anything that changes a
record on the OST -- a session's first write (`DIRTY`), `LEAVE`, a dropped
writer (`LOST`), `SYNC_PREPARE`/`SYNC_ACCEPT`, `SET_OWNER`, creating or
removing a chunk -- erases it before the change and after, on whichever
connection and worker it comes, so a writer's change shows in the next answer
to every other writer. A read that overlaps such a change is not kept.

The cache is sound only where the OST is the sole writer of its store, which
is how an instance is deployed (each instance has its own store). A change
made behind it -- `lvchange --addtag` or an edit of the meta file by hand, a
second `rawstor-ost` on the same store -- shows after the time to live at the
latest. The time to live is not what keeps the records right, the erasing is;
it only bounds how long such a change goes unseen, so it should be well above
`mirror_probe_interval` (5 s), or the records expire between two polls. The
cache is off for an `ost://` location (the records are the other
server's) and with `--meta-cache-ttl 0`.

## Registration with an MDS

With `--mds`, the OST enters itself in the topology of that MDS and keeps
itself there (see [OST registration](mds.md#ost-registration)): it registers
when it starts, again every heartbeat interval the MDS asks for, and as
leaving when it stops. With each registration it sends its latest sample of
the store -- the space `LOCATION_INFO` reports and the digest of the members
it holds -- taken at start, every info interval the MDS asks for, and shortly
after a member or a version was created or removed on it. A sample is taken
apart from the registrations, which go on while a large store is walked, and
is registered as soon as it is taken. A registration the MDS refuses, or one
it does not answer within a heartbeat interval, is logged once and made again
on a new connection; the OST serves on meanwhile, and is back within two
intervals of the MDS. The advertised location carries no user information.

```bash
rawstor-ost -b 0.0.0.0:7777 --id ${OST_ID} --mds mds://mds1:7776 \
    --advertise ost://host1:7777 --domain-path dc1/row1/rack1/host1 --weight 2000 \
    file:///var/rawstor/data
```

An OST is the only one to know its domain and weight, so a change is made
there: restart it with the new ones and the MDS takes them, logging a warning;
the chunks already placed stay where they are. All the members of the store
are taken to belong to the cluster of that MDS. The advertised location is any
single location URI: one the clients reach directly, such as the `file://`
store itself on a single host, works too.

## systemd instances

The `rawstor-ost` deb/rpm package ships the `rawstor-ost@.service`
template: one instance per OST, named after the OST's id (`--id`: the
`<uuid>` it registers under and its certificate is for), configured by
`/etc/rawstor/ost/<uuid>.conf`. Installing the package starts nothing; an
instance without its config refuses to start. A host runs as many
instances as it has OSTs, each on its own port and store.

The config is an environment file (`KEY=VALUE` lines):

| Key | Default | Description |
|-----|---------|-------------|
| `BIND_ADDR` | — (required) | `<ip>:<port>` to listen on, unique per host. |
| `LOCATION` | `file:///var/lib/rawstor/ost/<uuid>` | Backing store this instance serves. |
| `QUEUE_SIZE` | `4096` | `--queue-size`. |
| `WORKERS` | `12` | `--workers`. |
| `META_CACHE_TTL` | `60000` | `--meta-cache-ttl`. |
| `MDS` | empty | `--mds`; no registration while empty. |
| `ADVERTISE` | empty | `--advertise`. |
| `DOMAIN_PATH` | empty | `--domain-path`. |
| `WEIGHT` | `100` | `--weight`. |
| `RAWSTOR_TLS_*` | | TLS settings, see [Configuration](configuration.md#tls). |
| `RAWSTOR_OPTS_*` | | Tuning knobs, see [Configuration](configuration.md). |

The instance runs as the `rawstor` user under `ProtectSystem=strict`. Its
default store, `/var/lib/rawstor/ost/<uuid>` (`StateDirectory=`), is
created on start and owned by `rawstor`; a disk mounted there needs no
further configuration. A store anywhere else needs a per-instance drop-in
granting the sandbox access to it, and must be writable by `rawstor`:

```bash
sudo systemctl edit rawstor-ost@<uuid>.service
# [Service]
# ReadWritePaths=/srv/disk1/rawstor
```

Two OSTs on one host:

```bash
OST1=$(cat /proc/sys/kernel/random/uuid)
OST2=$(cat /proc/sys/kernel/random/uuid)
# Each instance has its own certificate, for spiffe://<trust domain>/ost/<id>:
# /etc/rawstor/tls/<id>.crt and <id>.key, see Configuration for TLS.
tls() {
    printf 'RAWSTOR_TLS_TRUST_DOMAIN=cluster.example\nRAWSTOR_TLS_CERT=/etc/rawstor/tls/%s.crt\nRAWSTOR_TLS_KEY=/etc/rawstor/tls/%s.key\nRAWSTOR_TLS_CA=/etc/rawstor/tls/ca.crt\n' $1 $1
}
mds() {
    printf 'MDS=mds://mds1:7776\nADVERTISE=ost://%s:%s\nDOMAIN_PATH=dc1/row1/rack1/%s\n' $(hostname) $1 $(hostname)
}
(echo BIND_ADDR=0.0.0.0:7777; tls ${OST1}; mds 7777) | sudo tee /etc/rawstor/ost/${OST1}.conf
(echo BIND_ADDR=0.0.0.0:7778; tls ${OST2}; mds 7778) | sudo tee /etc/rawstor/ost/${OST2}.conf
sudo systemctl enable --now rawstor-ost@${OST1} rawstor-ost@${OST2}

systemctl status rawstor-ost@${OST1}       # state
journalctl -u rawstor-ost@${OST1}          # log
rawstor location info ost://127.0.0.1:7777   # serving? (with RAWSTOR_TLS_* in the environment)
sudo systemctl restart rawstor-ost@${OST1}
```

Removing an instance never touches its store: stop and disable it, then
delete its config. Recreating the same config later serves the same data
again; the store itself is removed by hand, if at all.

```bash
sudo systemctl disable --now rawstor-ost@${OST2}
sudo rm /etc/rawstor/ost/${OST2}.conf
# data stays in /var/lib/rawstor/ost/${OST2}
```

A package upgrade restarts the running instances; removing the package
stops them, leaving configs, stores and enablement in place.
