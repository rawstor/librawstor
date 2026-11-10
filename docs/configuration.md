# Configuration

Environment variables tuning the Rawstor client and servers. Defaults are shown below.

| Variable | Default | Description |
|----------|---------|-------------|
| `RAWSTOR_LOCATION` | *(none)* | Fallback `LOCATION` for `rawstor create`/`list`/`info` when it's omitted from the command line. |
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

> **Note:** All timeout values are expressed in milliseconds unless stated otherwise.

An unset variable takes its default. A set one must be valid -- a plain
decimal integer within the variable's range (or, for a size, a number with a
unit) -- otherwise the program logs the variable and the accepted range and
exits with `EX_CONFIG` (78), which the shipped systemd units do not restart.
`0` is accepted only where it means something: it disables
`RAWSTOR_OPTS_SO_SNDTIMEO`, `RAWSTOR_OPTS_SO_RCVTIMEO`,
`RAWSTOR_OPTS_TCP_USER_TIMEOUT` and the retry backoff, and allows no backlog in
`RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY`.
