# Configuration

Environment variables tuning the RawStor client and servers. Defaults are shown below.

| Variable | Default | Description |
|----------|---------|-------------|
| `RAWSTOR_LOCATION` | *(none)* | Fallback `LOCATION` for `rawstor object create`, `rawstor object list`, `rawstor location info`, `rawstor location list` and `rawstor account` when it's omitted from the command line. Also the location a bare object UUID is resolved against wherever a `TARGET` is expected (see [Concepts](concepts.md#object-uuid-instead-of-a-target)). |
| `RAWSTOR_MDS_OPTS_INFO_INTERVAL` | `300000` | MDS backend INFO/health polling interval in milliseconds; each OST is polled once per interval at its own fixed offset, spreading probes evenly. Must be positive. |
| `RAWSTOR_MDS_OPTS_INFO_CONCURRENCY` | `128` | Maximum concurrent MDS backend probes, including retries (1–1024); see [MDS health and location information](mds.md#backend-health-and-location-information). |
| `RAWSTOR_MDS_OPTS_INFO_REFRESH_DELAY` | `5000` | Milliseconds after an object create, grow or remove before the OSTs holding its slots are probed again, ahead of their regular slot (`0` probes at once); see [MDS health and location information](mds.md#backend-health-and-location-information). |
| `RAWSTOR_OPTS_IO_ATTEMPTS` | `10` | Number of attempts for an I/O operation before giving up, covering any failure from a broken connection to a well-formed rejection from a live backend (e.g. `EBUSY`/`ENOSPC`) -- every retry reconnects first (except a plain `EBUSY`, where the session is fine and just backed up against the remote server's own write-throttling). A rejection known to never succeed on retry (e.g. `ENOENT`) isn't retried at all, regardless of this value. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE` | `100` | Base delay, in milliseconds (ms), before the first retry of an I/O operation; doubles with each further attempt, capped at `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX`. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX` | `30000` | Upper bound, in milliseconds (ms), on the exponential retry backoff delay above. |
| `RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER` | `50` | Percentage (0-100, not a time value) of the computed retry backoff delay that is randomized, to avoid many clients retrying in lockstep. `0` disables jitter (a plain exponential backoff); `100` is "Full Jitter" (the whole delay is randomized); `50` is "Equal Jitter" (half the delay is fixed, half is randomized). |
| `RAWSTOR_OPTS_SO_SNDTIMEO` | `5000` | Socket send timeout, in milliseconds (ms). Sets `SO_SNDTIMEO` for network sockets. |
| `RAWSTOR_OPTS_SO_RCVTIMEO` | `5000` | Socket receive timeout, in milliseconds (ms). Sets `SO_RCVTIMEO` for network sockets. |
| `RAWSTOR_OPTS_TCP_USER_TIMEOUT` | `5000` | TCP user timeout, in milliseconds (ms) (Linux `TCP_USER_TIMEOUT`). Defines how long transmitted data may remain unacknowledged before the connection is closed. |
| `RAWSTOR_OPTS_LIST_LIMIT` | `1000` | Server-side page size cap for list operations: the maximum number of objects returned in a single call, regardless of the caller-requested limit. Larger listings are paginated across multiple calls. |
| `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` | `128` | Per-session cap on writes dispatched to a `file://` backing store without their completion arriving yet; writes past the cap wait for a dispatch slot instead of being sent immediately. |
| `RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY` | `256M` | Per-session cap on writes queued behind `RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT` but not yet dispatched to a `file://` backing store; a write that would push the backlog over the cap fails with `EBUSY` instead of queuing. Takes a size in bytes, or with a unit suffix (`K`, `M`, `G`, `T`, `P`, `E`), e.g. `256M` or `4096`. |
| `RAWSTOR_OPTS_TLS_HANDSHAKE_LIMIT` | `1024` | Most TLS handshakes a server process (`rawstor-ost`, `rawstor-mds`) has in flight at once, over all its worker threads. A connection that arrives when that many are in progress is closed before anything is read from it, and counted and logged (a warning, at most once a second, with the number closed since the last one and in total). A handshake that has not completed has no identity, so this is what bounds the sockets and TLS state an unauthenticated peer can hold; set it well above the number of clients and OSTs that connect together. Has no effect without TLS. |

> **Note:** All timeout values are expressed in milliseconds unless stated otherwise.

An unset variable takes its default. A set one must be valid -- a plain
decimal integer within the variable's range (or, for a size, a number with a
unit) -- otherwise the program logs the variable and the accepted range and
exits with `EX_CONFIG` (78), which the shipped systemd units do not restart.
`0` is accepted only where it means something: it disables
`RAWSTOR_OPTS_SO_SNDTIMEO`, `RAWSTOR_OPTS_SO_RCVTIMEO`,
`RAWSTOR_OPTS_TCP_USER_TIMEOUT` and the retry backoff, and allows no backlog in
`RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY`.

## TLS

Every connection between rawstor processes -- a client to an OST or an MDS, an
OST to another OST -- runs over TLS 1.3 with mutual authentication; see the
[Security design](security.md). A process needs the first four of these, and
refuses to start with `EX_CONFIG` if it has none of them or only some.
[`rawstor pki`](#issuing-certificates) makes them for a cluster that has no CA.
The one way to run without TLS is to say so, with `--insecure`: see
[Without TLS](#without-tls).

| Variable | Description |
|----------|-------------|
| `RAWSTOR_TLS_TRUST_DOMAIN` | The trust domain of the cluster, the host part of every SPIFFE ID in it (`cluster.example` in `spiffe://cluster.example/ost/<uuid>`). A peer whose ID is in another trust domain is refused, whoever signed its certificate. |
| `RAWSTOR_TLS_CERT` | This process's certificate, PEM, with the chain to the CA if it is not the CA itself. It must have exactly one URI SAN, the process's SPIFFE ID, and the extended key usages `serverAuth` and `clientAuth`. |
| `RAWSTOR_TLS_KEY` | The private key of the certificate, PEM. |
| `RAWSTOR_TLS_CA` | The CAs a peer's certificate must chain to, PEM; several may be listed. |
| `RAWSTOR_TLS_CRL` | Optional: a CRL, PEM, checked for the peer's certificate. It must cover the CA. |
| `RAWSTOR_TLS_MDS_ID` | Optional: the id of the MDS this process connects to, a UUID, the last segment of its SPIFFE ID (`0198f1a2-…` for `spiffe://cluster.example/mds/0198f1a2-…`). Every `mds://` connection must then present exactly that ID. |

The SPIFFE ID of a process says what it is:

| ID | Process |
|----|---------|
| `spiffe://<trust_domain>/ost/<ost_id>` | an OST, `ost_id` being its id in the MDS topology |
| `spiffe://<trust_domain>/mds/<mds_id>` | an MDS |
| `spiffe://<trust_domain>/admin/<name>` | an operator or control plane |
| `spiffe://<trust_domain>/account/<account_id>/client/<name>` | an account's client |

A client takes a server to be an OST or an MDS by its ID: an `ost://` address
needs an OST and an `mds://` one an MDS. An OST the MDS has resolved must also
present the ID the MDS named for it, so one OST cannot answer for another. The
MDS is held to the id in `RAWSTOR_TLS_MDS_ID` when it is set; without it, as
for an `ost://` address the MDS has not named, any server of that role in the
trust domain is accepted, so set it wherever a client talks to one MDS.

The OST an address stands for is remembered by the address, for the life of the
process: when an OST is replaced at the same address, an object resolved before
the replacement fails to connect (the new OST's ID is not the one it was told)
until it is resolved again.

The certificate is read again, for the connections made after it, on `SIGHUP`
and `SIGUSR1` in `rawstor-ost` and `rawstor-mds`, and on `SIGUSR1` in
`rawstor-vhost` and `rawstor-vduse`, where `SIGHUP` already re-reads the size
of the object. The connections already open keep the certificate they started
with. A file that cannot be read is logged and the old certificate stays.
Session tickets are off, so each connection makes a full handshake.

### Issuing certificates

A cluster that has no CA of its own can make one with `rawstor pki`, which
needs no TLS settings itself. The CA is a directory with its certificate,
`ca.crt` (what every process lists as `RAWSTOR_TLS_CA`), and its private key,
`ca.key`, which stays on the machine that issues certificates:

```
rawstor pki init --trust-domain cluster.example ca
rawstor pki issue --ca ca --cert ost.crt --key ost.key ost       # a new id
rawstor pki issue --ca ca --cert mds.crt --key mds.key mds       # a new id
rawstor pki issue --ca ca --cert hv1.crt --key hv1.key admin hv1
rawstor pki issue --ca ca --cert vm.crt --key vm.key \
  --role none --object-permissions <object-uuid>:3 client <account-uuid> vm-1
rawstor pki renew --ca ca --cert ost.crt --key ost.key
rawstor pki show --cert ost.crt                                  # what it says
```

The `vm-1` example grants a virtual machine access only to its disk object:
replace `<account-uuid>` and `<object-uuid>` with the account and disk UUIDs.
Mask `3` permits reading, writing and discarding data.

A CA is made for the trust domain of one cluster and keeps it, so every
certificate it issues is in it. `issue` writes a certificate and a new key
(mode 0600) for a process, replacing the files. The process is `ost [ID]` (the
id is the one in the MDS topology, a UUID), `mds [ID]` (the id of the MDS, a UUID
as well), each with a new id if it is not given, `admin NAME` or
`client ACCOUNT NAME`. `renew` does the same for the
process of a certificate this CA issued, over the same files, and the running
process reads them again on `SIGHUP` or `SIGUSR1`.

`init` prints the CA the same way, with the columns `ca_dir`, `trust_domain`,
`ca_file` (`<dir>/ca.crt`, what a process lists as `RAWSTOR_TLS_CA`) and
`not_after` (when the CA expires, UTC).

`issue`, `renew` and `show` print what a certificate says, as the other
commands print their data (`--format table|json|value`, `--column`):
`identity` (the SPIFFE ID), `role`, `trust_domain`, `id` (of an OST or an MDS),
`name` (of an admin or a client), `account_id` (of a client), `not_after` (when it
expires, UTC) and `issued` (whether the CA signed it). The ones the role does
not have are empty, `null` in json; `--format value --column id` is how a script
gets the id of a new OST or MDS.

`show` reads a certificate and changes nothing: it is how the id is read from
a certificate that was issued earlier, and, given the CA with `--ca`, whether
that CA signed it (`issued` is `yes` or `no`, and empty without `--ca`). It
takes a certificate whoever issued it, as long as it names a process of
rawstor.

A certificate is valid for 7 days and a CA for 3650 unless `--validity` says
otherwise (a number and `s`, `m`, `h` or `d`). Keys are EC P-256. There is no
revocation beyond expiry and the optional `RAWSTOR_TLS_CRL`, so keep
certificates short.

The same is available to programs: `rawstor_pki_init()`, `rawstor_pki_issue()`
`rawstor_pki_renew()` and `rawstor_pki_show()` in `<rawstor/pki.h>`, which need no
`rawstor_initialize()`, and `rawstor.pki` (`init()`, `issue_ost()`,
`issue_mds()`, `issue_admin()`, `issue_client()`, `renew()`, `show()`) in
pyrawstor, which
does not start rawstor when imported, so a program can make its certificates and
set `RAWSTOR_TLS_*` before it first uses `Location` or `Target`.

Any other CA that writes the URI SAN fits as well, see
[Security design](security.md#issuing-certificates).

### Without TLS

Python programs call `rawstor.initialize(insecure=True)` before importing
`Location` or `Target`:

```python
import rawstor

rawstor.initialize(insecure=True)
location = rawstor.Location("ost://localhost:10000")
```

This disables TLS and peer authentication for the whole process. Leave all
`RAWSTOR_TLS_*` settings unset; combining them with `insecure=True` fails.
Without an explicit call, Python bindings require TLS. Initialization can be
repeated with the same mode, but changing the mode afterwards raises
`RuntimeError`.

`--insecure` on the command line of `rawstor`, `rawstor-ost`, `rawstor-mds`,
`rawstor-vhost`, `rawstor-vduse` and `rawstor-vhost-qemu` runs a process without
TLS: its connections are plaintext and **no peer is authenticated**, so every
peer that can reach a port can do everything. A program that links
librawstor sets `RawstorOpts::insecure`. Use it for a storage network that no
untrusted party can reach, and for development and tests.

The shipped systemd services accept additional command-line arguments through
`EXTRA_ARGS` in their existing configuration files:

| Service | Configuration file |
|---|---|
| `rawstor-ost@<uuid>` | `/etc/rawstor/ost/<uuid>.conf` |
| `rawstor-mds@<uuid>` | `/etc/rawstor/mds/<uuid>.conf` |
| `rawstor-vhost@<uuid>` | `/etc/rawstor-vhost.conf` |
| `rawstor-vduse@<uuid>` | `/etc/rawstor-vduse.conf` |

For example, `EXTRA_ARGS="--insecure"` runs a service without TLS;
`EXTRA_ARGS="--insecure --readonly"` also makes a vhost or vduse backend read-only.
The default is empty. systemd splits the value into arguments, respecting quoted
words; shell commands and variable expansion inside the value are not supported.
Restart the affected service instances after changing the configuration.

Insecure mode and the TLS settings exclude each other: a process started with
`--insecure` that has any `RAWSTOR_TLS_*` set, complete or not, refuses to
start. It logs `INSECURE` at start. A port is TLS or plaintext, never both and
never detected, so a plaintext process cannot talk to a TLS one, in either
direction; mixing the two in a cluster is meant only for moving it from one
mode to the other.


## Authorization

The client certificate carries its account (the SPIFFE identity), access role,
and optional object restrictions. Both MDS and OST authorize it directly:
there is no client registration, permission database, or signing key on MDS.
A client can use an OST directly while MDS is unavailable.

Issue client credentials on the CA machine:

```sh
rawstor pki issue --ca ca --cert client.crt --key client.key \
  --role manager client 018f4e2a-2222-7000-8000-000000000001 account-manager
```

`--role` is required for a client: `none` grants no default permissions,
`reader` reads and lists objects, `writer`
adds writes and discards, and `manager` adds creation, deletion and version
management. The process role shown as `role=client` is separate from the
`access_role` shown by `pki show`. Provider `admin` certificates manage accounts,
objects and ownership; `mds` certificates scan OST metadata. Neither provider
role may write data, and OST certificates grant no provider permissions.

To set explicit object permissions, repeat `--object-permissions UUID:MASK` when
issuing the certificate (at most 128 entries). The mask overrides the role's defaults:
`read=1`, `write=2`, `manage=4`; write includes discard and zeroing. Combine bits by addition, or use
zero to deny the object. Other objects retain the role's defaults. Object permissions
apply to the object and all its versions; snapshots remain read-only.

```sh
rawstor pki issue --ca ca --cert restricted-manager.crt --key restricted-manager.key \
  --role manager \
  --object-permissions 018f4e2a-2222-7000-8000-000000000002:1 \
  --object-permissions 018f4e2a-2222-7000-8000-000000000003:0 \
  client 018f4e2a-2222-7000-8000-000000000001 restricted-manager
rawstor pki show --cert restricted-manager.crt
```

For a vhost that may access only one object, use `none` and grant that UUID
read/write/discard (`3`):

```sh
rawstor pki issue --ca ca --cert vhost.crt --key vhost.key \
  --role none \
  --object-permissions 018f4e2a-2222-7000-8000-000000000002:3 \
  client 018f4e2a-2222-7000-8000-000000000001 vhost-1
```

All other objects, including ones created later, are denied. The same grant
covers the object's versions, whose data remains read-only. Use mask `1` and `rawstor-vhost --readonly` for
a read-only vhost. Mask `3` grants ordinary data I/O, not allocation, removal,
version management or repair that needs to allocate a replacement member.
A `none` client uses the supplied object target; account-wide `list` is denied.
MDS control connections may open to resolve an explicitly permitted object.

With admin credentials, create the account in MDS before creating its objects:

```sh
rawstor account create mds://mds:7776 --uuid 018f4e2a-2222-7000-8000-000000000001
```

A location without a named account uses the client certificate's account.
Naming another account is refused. OST checks the owner in local metadata;
foreign objects return `ENOENT`, insufficient permissions return `EACCES`.

`pki renew` preserves the signed role and restrictions. Use `pki issue` to
change permissions. The old certificate retains its permissions until expiry or
revocation; replacing a file does not revoke copies of it. Reload credentials
on clients to use the new certificate on new connections. The client library
reconnects an expired TLS connection with the reloaded credentials when retrying
I/O. Expiry is checked for
new commands on established account connections as well as during handshakes.
A configured CRL is checked on new TLS connections.

The C API in `<rawstor/pki.h>` accepts `RawstorPkiPermissions` in
`rawstor_pki_issue()` and returns it in `RawstorPkiInfo.permissions`.
Python `pki.issue_client(..., role="none", object_permissions={UUID: 3})` does
the same; `pki.show()` returns `access_role` and `object_permissions`.

An external CA must issue the [authorization extension](protocol.md#authorization)
in addition to the SPIFFE SAN. Missing permissions grant no account access;
malformed or duplicate extensions are rejected. Plaintext `--insecure`
deliberately bypasses authentication and authorization.
