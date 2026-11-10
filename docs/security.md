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
  availability and with metadata.
- Clients (`rawstor-vhost`, `rawstor-vduse`, the CLI) run on hypervisors that
  the provider operates. A guest VM never speaks the rawstor protocol itself,
  so a compromised guest reaches rawstor only through the volume it owns.
  Unlike an ordinary SDS client, the identity therefore belongs to a
  **volume attachment**, not to the host.

## Identity: mTLS

Every connection, whatever the role at the other end, is TLS 1.3 with mutual
authentication, implemented with OpenSSL. This gives transport encryption and
peer authentication in one mechanism and avoids a home-made handshake.

The identity of a peer is a URI SAN in its certificate:

```text
rawstor://<tenant_id>/<kind>/<name>      kind: client | ost | mds | admin
```

The scheme works with the project's own CA and with an external one: the
only requirement on a CA is that it can put a URI SAN into a certificate. The
certificate proves *who* the peer is; it carries no permissions (stage 3), so
rights can change without reissuing it.

Services verify the peer chain against a configured CA bundle, check
`extendedKeyUsage`, and take the identity from the SAN. A server role
(`ost`, `mds`) in a certificate is what stops a client from impersonating an
OST.

### Rotation without downtime

- Certificates are short-lived (hours to days). Revocation is by expiry, plus
  an optional CRL file reloaded with the rest.
- On `SIGHUP` a service rebuilds its `SSL_CTX` (certificate, key, CA bundle,
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
   TLS peer, and that `object_id` matches the one bound. The result is cached
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

## Plaintext mode and the cost of TLS

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

Decision rules for stage 0: kTLS at line rate with an acceptable CPU share
and p99 latency regression → TLS is mandatory everywhere, no plaintext mode.
Otherwise:

- the **control path** (MDS) is always TLS;
- the **data path** (OST) stays mTLS-authenticated but may be configured with
  an `integrity-only` option, only if a measured need exists, because TLS 1.3
  has no null cipher and this would be a second protocol, not a switch;
- a plain TCP mode exists only as an explicit, loudly-logged
  `--insecure` flag for development and tests, never as a default and never
  accepted by a service that has a certificate configured.

Until stage 0 is done, the working assumption is *TLS mandatory*.

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
- Zeros must survive encryption. An unwritten, discarded or `WRITE_ZEROES`'d
  area reads from the OST as zeros, which XTS would decrypt to garbage. The
  client therefore treats a sector whose ciphertext is all zeros as plaintext
  zeros and returns zeros without decrypting. `WRITE_ZEROES` and `DISCARD` go to
  the OST unchanged, sparseness is kept, and never-written areas read as zeros,
  as on a plain disk. A genuine ciphertext of all zeros has probability
  2^-128 per sector and is ignored. The only disclosure is "this sector is
  zero", which `DISCARD` and a sparse backend reveal anyway. The cost is a
  zero check per sector on read.
- Encryption costs CPU on the client (hypervisor), not on the OST.

## Implementation stages

Each stage is shippable and leaves the cluster working. Later stages do not
require re-doing earlier ones.

0. **Benchmark.** A throwaway harness comparing plain TCP, userspace
   OpenSSL TLS 1.3, and kTLS on the existing io_uring data path: 4 KiB and 1 MiB
   IO, queue depths 1 and 32, handshake rate, CPU per GB, p50/p99 latency.
   Output: the plaintext-mode decision above and the minimum kernel.
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
   deployments that have none; documentation for external CAs and for a
   renewal agent.
5. **At-rest, server side.** Documented ZFS/dm-crypt deployments; checks in
   `LOCATION_INFO` that the backend reports encryption, if useful.
6. **At-rest, client side.** AES-XTS in the client library, KMS plugin
   interface, wrapped keys on the MDS, `rawstor create --encrypt`, the
   all-zero-ciphertext rule.

## Open questions

- The exact kernel baseline for kTLS and the answer from stage 0.
- Whether one TLS connection per chunk slot stays, or stage 2 should coincide
  with the planned "one connection per (OST, object)" consolidation
  ([MDS design](mds.md)): handshake cost makes this likely.
- Where the KMS plugin lives (client library vs. a helper daemon on the
  hypervisor) and how a key reaches a vhost process at attach time.
- Whether `admin` rights are one role or split (tenant admin vs. operator).
