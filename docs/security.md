# Rawstor security design (DRAFT)

Authentication, authorization, transport and at-rest encryption, and the
groundwork for multi-tenancy. The deployment target is a **public cloud
service**: tenants are mutually untrusted, the storage network is not assumed
private, and the operator of an OST must not be able to read tenant data.

## Status

Legend: ✅ implemented · 🟡 partial · ❌ not implemented yet. *Stage* is this
document's own numbering (see [Implementation stages](#implementation-stages)).

| Feature | Stage | Status | Where |
|---|---|---|---|
| Benchmark: TLS 1.3 / kTLS on the io_uring hot path | 0 | ❌ | — |
| Protocol version + feature bits in the `SET_OBJECT` handshake | 1 | ❌ | also planned in [MDS design](mds.md) |
| `tenant_id` in the protocol and in the MDS store (single `default` tenant) | 1 | ❌ | — |
| mTLS (OpenSSL) on every port: OST, MDS, witness, client side | 2 | ❌ | — |
| kTLS offload of the data path | 2 | ❌ | decided by stage 0 |
| Certificate and CA reload without downtime | 2 | ❌ | — |
| Principals, roles, tenants in the MDS store, admin API | 3 | ❌ | — |
| Capability tokens issued by `RESOLVE`, checked by OST | 3 | ❌ | — |
| `rawstor pki` helper (own CA), external CA support | 4 | ❌ | — |
| At-rest encryption, server side (ZFS / dm-crypt) | 5 | ❌ | documentation only |
| At-rest encryption, client side (AES-XTS, wrapped per-object key) | 6 | ❌ | — |

## Threat model

- A network attacker can read, modify and inject traffic between any two
  rawstor processes, and can connect to any listening port.
- A tenant is untrusted: it must not read, write, list or delete another
  tenant's objects, and must not learn that they exist.
- An OST/MDS host administrator (or someone who steals a disk) is untrusted
  with respect to tenant **data** (stage 6). They are trusted with
  availability and with metadata. Integrity of encrypted data is not
  protected (see [At-rest encryption](#at-rest-encryption)): such an
  administrator can corrupt or roll back sectors.
- Clients (`rawstor-vhost`, `rawstor-vduse`, the CLI) run on hypervisors that
  the provider operates. A guest VM never speaks the rawstor protocol itself,
  so a compromised guest reaches rawstor only through the volume it owns.
  Unlike an ordinary SDS client, the identity therefore belongs to a
  **volume attachment**, not to the host.

## Identity: mTLS

Every connection, whatever the role at the other end, is TLS 1.3 with mutual
authentication, implemented with OpenSSL. This gives transport encryption and
peer authentication in one mechanism and avoids a home-made handshake.

The identity of a peer is a [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
in the certificate, as defined by the
[X509-SVID](https://github.com/spiffe/spiffe/blob/master/standards/X509-SVID.md)
standard: exactly one URI SAN, scheme `spiffe`. Rawstor uses the standard
format and invents none:

```text
spiffe://<trust_domain>/ost/<ost_id>               OST      (provider infrastructure)
spiffe://<trust_domain>/mds/<name>                 MDS      (provider infrastructure)
spiffe://<trust_domain>/admin/<name>               operator / control plane
spiffe://<trust_domain>/tenant/<tenant_id>/client/<name>   a tenant's client
```

- `<trust_domain>` names the cluster or cloud (lowercase letters, digits,
  `.`, `-`, `_`, at most 255 bytes). A service accepts only IDs of its own
  trust domain, so a certificate from another cluster is rejected even if the
  same CA signed it.
- Path segments are letters, digits, `.`, `-`, `_`, case-sensitive; the whole
  ID is at most 2048 bytes. Ids are UUIDs in their canonical text form.
- Only clients carry a tenant. OSTs and MDSs belong to the provider, so
  their IDs have none. A tenant's client can never present an ID under
  `/ost/`, `/mds/` or `/admin/`: the issuing side decides the path, the
  service only parses it.
- The ID is taken from the URI SAN alone, never from the subject or a DNS
  name. A certificate with zero or several URI SANs is rejected.

Any CA that can write a URI SAN fits: SPIRE, Vault PKI, step-ca, cert-manager
or the project's own helper (stage 4). See [Issuing certificates](#issuing-certificates).
The certificate proves *who* the peer is; it carries no permissions (stage 3),
so rights can change without reissuing it.

A client never accepts "any certificate from the trusted CA" as the server.
Every connection has an **expected server identity** that comes from trusted
configuration, not from the peer: for an MDS, the identity configured next to
its address; for an OST, `spiffe://<trust_domain>/ost/<ost_id>` where `ost_id` is
the one the MDS returns in `RESOLVE` (the topology's OST UUID). A handshake
whose peer SAN differs fails. Servers verify the client the same way against
the tenant and role rules of stage 3.

Services verify the peer chain against a configured CA bundle, check
`extendedKeyUsage`, and take the identity from the URI SAN. A server role
(`/ost/`, `/mds/` in the path) is what stops a client from impersonating an
OST.

### Issuing certificates

Rawstor consumes certificates from files and does not depend on how they are
produced. Tools that fit (versions as of November 2026, from the projects'
published pages, to be re-checked when the choice is made):

- **SPIRE** (latest release listed on spiffe.io: 1.15.2). A server plus an
  agent per host. The agent attests the *process* asking for an identity (the
  Unix workload attestor offers selectors such as `unix:uid`, `unix:gid`, and
  the binary path and `sha256` when path discovery is enabled) and issues a
  short-lived X.509-SVID; registration entries map selectors to a SPIFFE ID.
  Node attestors cover Kubernetes, AWS, Azure and others. This is the closest
  match for per-attachment identities: a `rawstor-vhost` process on a
  hypervisor gets an ID under its tenant. The control plane must create a
  registration entry per attach, which is integration work outside rawstor.
- **spiffe-helper** (latest release I could confirm: v0.9.1, January 2025;
  check for newer). Fetches X.509-SVIDs and bundles from the agent's Workload
  API and writes them to disk; on renewal it sends a configurable signal
  (default `SIGUSR1`) to a managed process or to the PID in a file. It does
  not forward signals or exit codes, so the service runs under systemd and
  is signalled by pid file. Rawstor therefore needs to reload on that signal
  as well as on `SIGHUP`, and needs no SPIFFE client library.
- **Vault PKI**, **step-ca**, **cert-manager**: issue a certificate with a
  URI SAN on request or by ACME, without attestation. Adequate when the
  deployment tool already knows which process gets which tenant.
- The project's own `rawstor pki` (stage 4) for installations with none of
  the above.

### Rotation without downtime

- Certificates are short-lived (hours to days). Revocation is by expiry, plus
  an optional CRL file reloaded with the rest.
- On `SIGHUP` (and `SIGUSR1`, which spiffe-helper sends by default) a service rebuilds its `SSL_CTX` (certificate, key, CA bundle,
  CRL) and uses the new one for **new** connections. Established connections
  keep their session until they close or reach a configured maximum age, after
  which the peer reconnects. The client already survives reconnects (see
  [Mirroring](mirroring.md)).
- A CA bundle may hold several CAs, so CA rotation is: add the new CA
  everywhere, start issuing from it, remove the old CA.
- Clients re-read their certificate on every reconnect, so a renewal agent
  needs only to replace the files.

## Authorization: capability tokens

mTLS says who is calling. Whether they may touch an object is decided once,
by the MDS, and then proven to the OST by a token, so the OST never calls the
MDS on the IO path.

1. The client sends `RESOLVE` / `OBJ_*` to the MDS. The MDS checks the
   principal's tenant and role against the object's tenant.
2. `RESOLVE` returns, with each chunk location, a **token**:
   `{tenant_id, object_id, rights (read | write | discard | admin),
   not_after, client certificate fingerprint}`, signed by the MDS.
3. The client sends the token in `SET_OBJECT` to the OST. The OST verifies the
   signature, the expiry, that the fingerprint equals that of the connection's
   TLS peer, and that **both** `tenant_id` and `object_id` match those in the
   `SET_OBJECT` (object ids are only unique within a tenant, so the pair is the
   key). The tenant of the token must also equal the tenant in the peer's
   certificate. The result is cached
   in the connection's Slot. The token is verified once per connection, not
   per request.

Choices:

- **Ed25519 signature, not HMAC.** The OSTs hold only the MDS public key, so
  a compromised OST cannot mint tokens for other OSTs. The key is identified
  by a key id, so it can be rotated with two keys valid at once.
- **Binding to the connection's certificate** makes a leaked token useless
  without the matching private key.
- **Short lifetime** (minutes). Long-lived connections renew by sending a new
  token in a fresh `SET_OBJECT`-like command (`RENEW`, to be defined in the
  protocol page); an expired token on an open connection fails new
  commands with `-EACCES` and the client re-resolves.
- `FREEZE`/`THAW` and the other lease holders keep their own tokens; they
  additionally require the `admin` right.

Which commands need which right is a table in the protocol page; it is a
closed list per command.

## Tenants

A tenant is the unit of isolation, ownership and (later) quota. Options
considered:

| Option | For | Against |
|---|---|---|
| A. Static file (like `topology.conf`) | trivial | no API, every change is a reload, cannot be driven by a cloud control plane |
| B. Records in the MDS store, small admin API | the control plane drives it; same store and failover as everything else; offline `--reconstruct` stays honest | rawstor grows a (small) user model |
| C. Delegate to an external IdP (OIDC), MDS only validates tokens | no user model in rawstor | an IdP becomes a hard dependency of the data path's setup; token format work |

**Recommendation: B**, with the CA (own or external) being the only trust
anchor shared with the outside. The MDS stores `tenant`, `principal`
(certificate subject → tenant, role) and an object's `tenant_id`. The cloud
control plane creates tenants and principals through the admin API (an `admin`
principal), then issues certificates. C can be layered on later by a service
that maps an OIDC identity to a rawstor certificate; it needs nothing from
the core.

Groundwork that is cheap now and expensive later (stage 1):

- every object id is scoped by `tenant_id` (128 bit, nil-free; `default` is a
  fixed UUID) in the MDS store, in `LIST`, in the OST slot key and in the
  on-disk metadata the OST keeps per chunk;
- the protocol carries `tenant_id` where `object_id` is carried, and the
  `SET_OBJECT` handshake advertises a protocol version and feature bits so
  a mixed cluster can be upgraded;
- `LIST` and `--reconstruct` take a tenant and never cross tenants.

Quotas, rate limits and noisy-neighbour control are a separate task.

## The cost of TLS on the hot path

The hot path is the question here, and the answer should come from a
measurement (stage 0), not from an assumption.

What to expect: with AES-NI, AES-GCM is typically several GB/s per core, so
the throughput cost is a share of CPU, not a ceiling. The larger risks are
structural:

- userspace TLS (`SSL_read`/`SSL_write`) adds a copy per direction and
  breaks io_uring zero-copy receive of data into the caller's buffer;
- **kTLS** moves the record layer to the kernel after an userspace
  handshake, so the existing io_uring `send`/`recv` code mostly keeps working.
  Whether `SEND_ZC`, multishot receive and registered buffers still work, and
  what kernel versions are required, is what stage 0 establishes;
- latency of small IO (4 KiB) matters more than bulk bandwidth for block
  storage; TLS record overhead and a handshake per connection (one connection
  per chunk slot today) are the numbers to look at. Session resumption and
  connection reuse are the mitigations.

Decision rule for stage 0: it decides **how** TLS is done (kTLS or userspace,
connection reuse, minimum kernel), not **whether**. TLS is mandatory on every
port, the OST data path included. An integrity-only mode is rejected: until
client-side encryption exists, and for every plain volume after it, the data
on the wire is tenant data, and TLS 1.3 has no null cipher anyway. If the
measurement shows an unacceptable cost, the answer is engineering (kTLS,
hardware, fewer handshakes), not weaker transport.

The one exception is an explicit, loudly-logged `--insecure` flag for
development and tests: never a default, and never accepted by a service that
has a certificate configured.


## At-rest encryption

Two layers, because they answer different threats.

**Server side (stage 5)** protects against stolen or retired disks. It needs
no protocol change: ZFS native encryption or dm-crypt under the OST backend,
with the key held by the host. Rawstor documents the supported setups; the OST
gains no key logic.

**Client side (stage 6)** protects against the OST/MDS operator. Data is
encrypted by the client library before it leaves the process, so an OST stores
ciphertext and never holds a key. This matches the project's principle that
any data transformation belongs in the client.

- Cipher: **AES-256-XTS**, as dm-crypt and LUKS use for block devices: no
  size expansion, in-place overwrite, chunk size unchanged.
- Tweak: derived from `(object_id, logical offset)`, never from a physical
  location, so a chunk can move between OSTs and a native snapshot stays
  readable.
- Keys: a random data key per object, stored **wrapped** in the object's
  metadata on the MDS by a per-tenant key-encryption key held by a KMS
  (Vault / KMIP / a cloud KMS), reached through a plugin interface. The MDS and
  OST never see a plaintext data key. Versions (snapshots) share the data key of
  their object; a clone gets a new one and is re-encrypted by the client.
- The MDS stores `crypto_params` (algorithm, key id, wrapped key) per object.
  The field is reserved already in stage 1.

Consequences that need to be accepted or handled:

- XTS gives confidentiality, not integrity: an OST operator can corrupt or
  replay sectors undetected. The xxh3 in the protocol is not cryptographic.
  An AEAD mode needs per-sector metadata and a changed chunk layout; it is a
  possible later stage, not part of this plan.
- Encryption is a property of the volume, chosen at creation
  (`rawstor create --encrypt`) and fixed for its life: an object has
  `crypto_params` or it has not. Plain volumes are unchanged. There is no
  sparseness optimisation for encrypted ones, so the OST can never be asked
  to "forge" a zero sector and the semantics are those of dm-crypt/LUKS:
  - `WRITE_ZEROES` is turned by the client into an ordinary write of encrypted
    zeros; the range stops being sparse on the OST;
  - `DISCARD` is not advertised to the guest, so it writes zeros itself
    (an `allow_discards` option may follow, with the dm-crypt caveat that
    freed blocks become visible);
  - a never-written area reads from the OST as zeros, which decrypt to garbage.
    Guests do not depend on the content of blocks they have not written; this
    goes to [Known limitations](limitations.md) when implemented.
- Encryption costs CPU on the client (hypervisor), not on the OST.

## Implementation stages

Each stage is shippable and leaves the cluster working. Later stages do not
require re-doing earlier ones.

0. **Benchmark.** A throwaway harness comparing plain TCP, userspace
   OpenSSL TLS 1.3, and kTLS on the existing io_uring data path: 4 KiB and 1 MiB
   IO, queue depths 1 and 32, handshake rate, CPU per GB, p50/p99 latency.
   Output: the TLS mode (kTLS or userspace) and the minimum kernel.
1. **Protocol groundwork.** Version + feature bits in the handshake;
   `tenant_id` in protocol, MDS store, OST slot key, `LIST`; `crypto_params`
   reserved in the object record. Single `default` tenant; behaviour unchanged.
2. **Transport.** An OpenSSL layer under `rawio` (client and server side),
   mTLS, identity extraction from the SAN, config options on every service,
   reload on `SIGHUP`, `--insecure` for tests. kTLS if stage 0 says so. Service
   and CLI test suites run over TLS.
3. **Authorization.** Tenants, principals and roles in the MDS store and admin
   API; capability tokens in `RESOLVE`, verified by the OST; per-command rights
   table; `-EACCES` / `-ENOENT` semantics (a foreign object is `-ENOENT`).
4. **PKI tooling.** `rawstor pki` to run a small CA (init, issue, renew) for
   deployments that have none; documentation for SPIRE (with spiffe-helper)
   and other external CAs.
5. **At-rest, server side.** Documented ZFS/dm-crypt deployments; checks in
   `LOCATION_INFO` that the backend reports encryption, if useful.
6. **At-rest, client side.** AES-XTS in the client library, KMS plugin
   interface, wrapped keys on the MDS, `rawstor create --encrypt`, the
   write-zeroes emulation and no `DISCARD`.

## Open questions

- The exact kernel baseline for kTLS and the answer from stage 0.
- Whether one TLS connection per chunk slot stays, or stage 2 should coincide
  with the planned "one connection per (OST, object)" consolidation
  ([MDS design](mds.md)): handshake cost makes this likely.
- Where the KMS plugin lives (client library vs. a helper daemon on the
  hypervisor) and how a key reaches a vhost process at attach time.
- Whether `admin` rights are one role or split (tenant admin vs. operator).
