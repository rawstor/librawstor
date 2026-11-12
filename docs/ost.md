# rawstor-ost – OST Protocol Server

`rawstor-ost` implements the **OST protocol** (see [Protocol](protocol.md)), handling network connections and providing access to data stored in one backend **location** (as defined in the [Concepts](concepts.md) documentation).

- `file://` scheme → serves data directly from the local filesystem.
- `ost://` scheme → acts as a proxy to an underlying OST backend.
- Comma‑separated list → supports mirroring or data locality.

## Usage

`rawstor-ost [-h] -b ADDR LOCATION`

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit. |
| `LOCATION` | Comma‑separated list of backend locations (e.g., `file:///path`, `ost://host:port`). |
| `-b, --bind ADDR` | Bind address in `<ip>[:<port>]` format (e.g., `127.0.0.1:7777`); the port defaults to 7777. |
| `-w, --workers N` | Number of worker threads, each with its own client connections and I/O queue, all accepting on the same listening socket (default: `12`). |

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

## systemd instances

The `rawstor-ost` deb/rpm package ships the `rawstor-ost@.service`
template: one instance per OST, named after the OST's id (the `<uuid>` the
MDS topology lists it under), configured by
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
echo "BIND_ADDR=0.0.0.0:7777" | sudo tee /etc/rawstor/ost/${OST1}.conf
echo "BIND_ADDR=0.0.0.0:7778" | sudo tee /etc/rawstor/ost/${OST2}.conf
sudo systemctl enable --now rawstor-ost@${OST1} rawstor-ost@${OST2}

systemctl status rawstor-ost@${OST1}       # state
journalctl -u rawstor-ost@${OST1}          # log
rawstor location info ost://127.0.0.1:7777          # serving?
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
