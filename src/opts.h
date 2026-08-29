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
//     unsigned int io_wire_retry_attempts;
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

// Number of reconnect+retry attempts Connection::_with_retry() makes for
// a "wire" failure -- couldn't even talk to the backend (connect
// failure, broken connection, corrupt/unexpected frame on the wire) --
// as opposed to a well-formed rejection *from* a live backend, which
// rawstor_opts_io_attempts() governs instead. Same default as
// io_attempts (3): only deployments that explicitly want QEMU
// `reconnect=N`-style unbounded retry (rawstor-vhost/-vduse's own
// packaged systemd units do, via RAWSTOR_OPTS_IO_WIRE_RETRY_ATTEMPTS=-1,
// which this reads as UINT_MAX) get it.
unsigned int rawstor_opts_io_wire_retry_attempts(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OPTS_H
