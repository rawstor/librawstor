# TLS cost benchmark (security design, stage 0)

Measures what TLS 1.3 costs on a rawstor-like data path, to decide *how* TLS is
done (kTLS or userspace, connection reuse, minimum kernel); see
[`docs/security.md`](../../docs/security.md).

```bash
sudo modprobe tls            # kTLS
./run.sh                     # ./results/{raw.txt,summary.md}
SECS=5 REPS=5 CPU_S=4 CPU_C=5 OUT=/tmp/r ./run.sh
```

Needs `gcc`, `liburing-dev` (2.3+: `send_zc`, buffer rings), `libssl-dev`
(OpenSSL 3.x), `openssl`, `python3`. It is not part of the autotools build.

## What is compared

| Transport | Meaning |
|---|---|
| `plain` | TCP, `io_uring` `send`/`recv` |
| `ktls` | OpenSSL handshake, then kernel TLS records; the same `io_uring` ops as `plain` |
| `ubio` | userspace OpenSSL over memory BIOs; `io_uring` moves the ciphertext |
| `ufd` | userspace OpenSSL `SSL_read`/`SSL_write` on the socket (reference) |

Every TLS run is mutual (client certificate verified), TLS 1.3, X25519,
ECDSA P-256 certificates with a SPIFFE-style URI SAN.

Workloads: 1 MiB streams in both directions, 4 KiB request/response at queue
depth 1 and 32 (a WRITE with a 4 KiB request and a READ with a 4 KiB reply),
connection setup (TCP only, full handshake, resumed), and a probe of which
`io_uring` operations still work on a kTLS socket.

## Limits of the method

- **Loopback.** No NIC, no network latency: the numbers are CPU cost and the
  latency added by the software path. Real links add their own time.
- **One connection per workload**, server and client on separate pinned cores.
  Real hosts run many connections on many cores, so per-core cost is the
  quantity to extrapolate from, not the absolute GB/s.
- **One synchronous `io_uring` operation at a time**, the way a QD1 caller
  works. It does not reproduce rawstor's batching or multishot receive in the
  stream tests; the probes cover the features separately.
- **The CPU is whatever it is.** Without VAES/AVX-512 (`openssl speed` shows
  the AES-GCM rate) AES-GCM is several times slower than on recent cores.
  Re-run on production hardware before relying on absolute numbers.
- Cipher-suite choice: AES-256-GCM and AES-128-GCM. ChaCha20-Poly1305 is not
  measured.
