#ifndef RAWSTOR_OPTS_H
#define RAWSTOR_OPTS_H

#include <rawstor.h>

#ifdef __cplusplus
extern "C" {
#endif

// defined in rawstor.h
// struct RawstorOpts {
//     unsigned int io_attempts;
//     unsigned int sessions;
//     unsigned int so_sndtimeo;
//     unsigned int so_rcvtimeo;
//     unsigned int tcp_user_timeout;
//     unsigned int list_limit;
//     unsigned int write_throttle_limit;
//     unsigned int write_backlog_capacity;
//     unsigned int io_retry_backoff_base;
//     unsigned int io_retry_backoff_max;
//     unsigned int io_retry_backoff_jitter;
//     unsigned int mirror_probe_interval;
// };

int rawstor_opts_initialize(const struct RawstorOpts* opts);

void rawstor_opts_terminate(void);

unsigned int rawstor_opts_io_attempts(void);

unsigned int rawstor_opts_sessions(void);

unsigned int rawstor_opts_so_sndtimeo(void);

unsigned int rawstor_opts_so_rcvtimeo(void);

unsigned int rawstor_opts_tcp_user_timeout(void);

unsigned int rawstor_opts_list_limit(void);

unsigned int rawstor_opts_write_throttle_limit(void);

unsigned int rawstor_opts_write_backlog_capacity(void);

// Base delay (ms) of the exponential backoff Connection::_with_retry()
// waits between retry attempts -- doubled once per already-failed
// attempt, capped at rawstor_opts_io_retry_backoff_max().
unsigned int rawstor_opts_io_retry_backoff_base(void);

// Cap (ms) on the exponential backoff delay above, reached once
// io_attempts is high enough for the doubling to exceed it.
unsigned int rawstor_opts_io_retry_backoff_max(void);

// Percentage (0-100) of the computed backoff delay that gets randomized:
// 0 disables jitter (a purely deterministic exponential backoff), 100 is
// "Full Jitter" (delay = random(0, computed)), 50 is "Equal Jitter"
// (computed / 2 + random(0, computed / 2)) -- see
// https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/.
unsigned int rawstor_opts_io_retry_backoff_jitter(void);

// How often, in milliseconds, an open mirrored object probes its
// unreachable arms for reconnection (and resyncs them on success).
unsigned int rawstor_opts_mirror_probe_interval(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OPTS_H
