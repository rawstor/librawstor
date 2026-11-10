# TLS cost on the io_uring data path (loopback)

`kernel 7.0.0-38-generic  openssl 3.5.5  cpus 2/3`

## Streams, 1 MiB messages, one connection

Throughput and CPU seconds per GB (client + server, user + kernel).

| cipher | direction | transport | GB/s | CPU s/GB | vs plain (GB/s) |
|---|---|---|---|---|---|
| AES_256_GCM_SHA384 | up | plain TCP | 3.07 | 0.53 | 100% |
| AES_256_GCM_SHA384 | up | kTLS | 1.10 | 1.40 | 36% |
| AES_256_GCM_SHA384 | up | userspace TLS (memory BIO) | 1.43 | 1.25 | 47% |
| AES_256_GCM_SHA384 | up | userspace TLS (SSL on fd) | 1.20 | 1.44 | 39% |
| AES_256_GCM_SHA384 | down | plain TCP | 3.42 | 0.47 | 100% |
| AES_256_GCM_SHA384 | down | kTLS | 1.40 | 1.24 | 41% |
| AES_256_GCM_SHA384 | down | userspace TLS (memory BIO) | 1.46 | 1.25 | 43% |
| AES_256_GCM_SHA384 | down | userspace TLS (SSL on fd) | 0.98 | 1.75 | 29% |
| AES_128_GCM_SHA256 | up | kTLS | 1.25 | 1.19 | 41% |
| AES_128_GCM_SHA256 | up | userspace TLS (memory BIO) | 1.44 | 1.28 | 47% |
| AES_128_GCM_SHA256 | up | userspace TLS (SSL on fd) | 1.10 | 1.49 | 36% |
| AES_128_GCM_SHA256 | down | kTLS | 1.49 | 1.22 | 44% |
| AES_128_GCM_SHA256 | down | userspace TLS (memory BIO) | 1.48 | 1.26 | 43% |
| AES_128_GCM_SHA256 | down | userspace TLS (SSL on fd) | 1.10 | 1.57 | 32% |

## Request/response, 4 KiB payload

`w` = 4 KiB request + 16 B response (a WRITE); `r` = 48 B request + 4 KiB response (a READ). One connection. CPU is client + server per operation.

| op | queue depth | transport | IOPS | p50 µs | p99 µs | p99.9 µs | CPU µs/op |
|---|---|---|---|---|---|---|---|
| w | 1 | plain TCP | 30,805 | 32.1 | 57.9 | 77.2 | 34.4 |
| w | 1 | kTLS | 28,620 | 31.0 | 70.6 | 96.5 | 39.7 |
| w | 1 | userspace TLS (memory BIO) | 22,308 | 43.6 | 73.5 | 99.9 | 47.9 |
| w | 1 | userspace TLS (SSL on fd) | 22,868 | 41.4 | 70.7 | 95.7 | 44.4 |
| w | 32 | plain TCP | 117,258 | 263.9 | 397.3 | 474.4 | 15.3 |
| w | 32 | kTLS | 69,303 | 436.2 | 777.2 | 847.9 | 25.5 |
| w | 32 | userspace TLS (memory BIO) | 105,357 | 289.6 | 531.1 | 593.9 | 18.6 |
| w | 32 | userspace TLS (SSL on fd) | 69,233 | 455.1 | 662.4 | 765.7 | 27.4 |
| r | 1 | plain TCP | 28,850 | 32.1 | 57.1 | 76.1 | 36.2 |
| r | 1 | kTLS | 23,114 | 43.0 | 83.3 | 109.4 | 47.4 |
| r | 1 | userspace TLS (memory BIO) | 31,211 | 29.0 | 57.0 | 79.3 | 37.0 |
| r | 1 | userspace TLS (SSL on fd) | 29,024 | 30.8 | 66.1 | 86.6 | 36.9 |
| r | 32 | plain TCP | 113,938 | 270.1 | 451.9 | 518.8 | 15.4 |
| r | 32 | kTLS | 70,250 | 413.0 | 966.9 | 1058.0 | 25.5 |
| r | 32 | userspace TLS (memory BIO) | 102,532 | 292.6 | 513.1 | 589.2 | 19.2 |
| r | 32 | userspace TLS (SSL on fd) | 76,077 | 405.7 | 639.7 | 718.7 | 24.7 |

## Connection setup (mTLS, ECDSA P-256, X25519)

| setup | connections/s | CPU ms/connection (both sides) |
|---|---|---|
| TCP connect only | 17,954 | 0.070 |
| full TLS 1.3 handshake | 567 | 1.863 |
| resumed (session ticket) | 1,159 | 0.972 |

## io_uring features on a kTLS socket

256 KiB of a known pattern echoed through the server; the result is `ok` only if every byte matches.

| operation | plain | kTLS |
|---|---|---|
| `send` | ok | ok |
| `sendmsg` | ok | ok |
| `send_zc` | ok | FAIL(Operation not supported) |
| `send_zc_fixed` | ok | FAIL(Operation not supported) |
| `write_fixed` | ok | ok |
| `recv_bufsel` | ok | ok |
| `recv_multishot` | ok | ok |
| `read_fixed` | ok | ok |
| `sendfile` | ok | ok |

## How to read these numbers

- Machine: an 8-vCPU VM (AMD EPYC-Rome, no VAES/AVX-512; `openssl speed`
  gives AES-256-GCM about 3.2 GB/s per core), kernel 7.0.0-38, OpenSSL 3.5.5,
  liburing 2.14, loopback. Server and client are pinned to two separate cores.
  Run: `SECS=4 REPS=3`, medians of three runs.
- The spread between the three runs is large for small IO, up to about
  ±30-50% (for example kTLS, 4 KiB write at queue depth 1: 20,000 / 28,600 /
  31,000 IOPS; plain TCP 4 KiB write at queue depth 32: 111,000 / 117,000 /
  182,000). **Differences between the TLS transports on small IO are not
  resolved by this run**; only "TLS versus plain" and the bulk numbers are.
  Bulk: plain 3.1-4.1 GB/s, the TLS transports 1.0-1.7 GB/s, all runs.
- Loopback only: no NIC and no network latency.
