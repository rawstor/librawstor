#include "opts.h"

#include <rawstd/env.h>
#include <rawstd/logging.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>

#define RAWSTOR_OPTS_IO_ATTEMPTS 10
#define RAWSTOR_OPTS_SESSIONS 1
#define RAWSTOR_OPTS_SO_SNDTIMEO 5000
#define RAWSTOR_OPTS_SO_RCVTIMEO 5000
#define RAWSTOR_OPTS_TCP_USER_TIMEOUT 5000
#define RAWSTOR_OPTS_LIST_LIMIT 1000
#define RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT 128
#define RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY (256u * 1024 * 1024)
// base*(1+2+4+...+256) -- 9 waits before the 10th, final attempt, none
// of them hitting the max cap -- sums to a 51.1s worst-case time-to-
// final-failure (~38s average once RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER
// shaves its usual amount off), comfortably inside a 30-120s target for
// a client that should stall through a backend blip rather than give up
// too eagerly. Keeping the base itself small (100ms) matters just as
// much as the total: the first retry, by far the most likely one to
// actually matter (most blips clear in well under a second), should
// fire almost immediately, not sit through a multi-second delay meant
// for the failures deep enough into the budget to actually need it.
#define RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE 100
#define RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX 30000
#define RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER 50
#define RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL 5000

static struct RawstorOpts _rawstor_opts = {};

// Millisecond values that get scaled to microseconds in an unsigned int.
#define RAWSTOR_OPTS_MAX_MS (UINT_MAX / 1000)

// A nonzero `given` (set by the RawstorOpts caller) wins over the
// environment; either must lie within [min, max].
static int resolve(
    unsigned int given, const char* name, int bytes, unsigned int def,
    unsigned int min, unsigned int max, unsigned int* out
) {
    if (given != 0) {
        if (given < min || given > max) {
            rawstd_error(
                "Invalid RawstorOpts value %u for %s: expected %u to %u\n",
                given, name, min, max
            );
            return -EINVAL;
        }
        *out = given;
        return 0;
    }
    return bytes ? rawstd_env_bytes(name, def, min, max, out)
                 : rawstd_env_uint(name, def, min, max, out);
}

int rawstor_opts_initialize(const struct RawstorOpts* opts) {
    struct RawstorOpts given = {};
    if (opts != NULL) {
        given = *opts;
    }
    struct RawstorOpts resolved = {};
    const struct {
        unsigned int given;
        const char* name;
        int bytes;
        unsigned int def;
        unsigned int min;
        unsigned int max;
        unsigned int* out;
    } options[] = {
        {given.io_attempts, "RAWSTOR_OPTS_IO_ATTEMPTS", 0,
         RAWSTOR_OPTS_IO_ATTEMPTS, 1, UINT_MAX, &resolved.io_attempts},
        {given.sessions, "RAWSTOR_OPTS_SESSIONS", 0, RAWSTOR_OPTS_SESSIONS, 1,
         UINT_MAX, &resolved.sessions},
        // Zero disables each of these timeouts.
        {given.so_sndtimeo, "RAWSTOR_OPTS_SO_SNDTIMEO", 0,
         RAWSTOR_OPTS_SO_SNDTIMEO, 0, UINT_MAX, &resolved.so_sndtimeo},
        {given.so_rcvtimeo, "RAWSTOR_OPTS_SO_RCVTIMEO", 0,
         RAWSTOR_OPTS_SO_RCVTIMEO, 0, UINT_MAX, &resolved.so_rcvtimeo},
        // TCP_USER_TIMEOUT is an int to the kernel.
        {given.tcp_user_timeout, "RAWSTOR_OPTS_TCP_USER_TIMEOUT", 0,
         RAWSTOR_OPTS_TCP_USER_TIMEOUT, 0, INT_MAX, &resolved.tcp_user_timeout},
        {given.list_limit, "RAWSTOR_OPTS_LIST_LIMIT", 0,
         RAWSTOR_OPTS_LIST_LIMIT, 1, UINT_MAX, &resolved.list_limit},
        {given.write_throttle_limit, "RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT", 0,
         RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT, 1, UINT_MAX,
         &resolved.write_throttle_limit},
        {given.write_backlog_capacity, "RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY", 1,
         RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY, 0, UINT_MAX,
         &resolved.write_backlog_capacity},
        {given.io_retry_backoff_base, "RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE", 0,
         RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE, 0, RAWSTOR_OPTS_MAX_MS,
         &resolved.io_retry_backoff_base},
        {given.io_retry_backoff_max, "RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX", 0,
         RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX, 0, RAWSTOR_OPTS_MAX_MS,
         &resolved.io_retry_backoff_max},
        {given.io_retry_backoff_jitter, "RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER",
         0, RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER, 0, 100,
         &resolved.io_retry_backoff_jitter},
        {given.mirror_probe_interval, "RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL", 0,
         RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL, 1, RAWSTOR_OPTS_MAX_MS,
         &resolved.mirror_probe_interval},
    };
    // Every option is checked, so one run reports every invalid one.
    int res = 0;
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
        int r = resolve(
            options[i].given, options[i].name, options[i].bytes, options[i].def,
            options[i].min, options[i].max, options[i].out
        );
        if (r != 0 && res == 0) {
            res = r;
        }
    }
    if (res != 0) {
        return res;
    }
    _rawstor_opts = resolved;
    return 0;
}

void rawstor_opts_terminate(void) {
    /**
     * Free opts here.
     */
}

unsigned int rawstor_opts_io_attempts(void) {
    return _rawstor_opts.io_attempts;
}

unsigned int rawstor_opts_sessions(void) {
    return _rawstor_opts.sessions;
}

unsigned int rawstor_opts_so_sndtimeo(void) {
    return _rawstor_opts.so_sndtimeo;
}

unsigned int rawstor_opts_so_rcvtimeo(void) {
    return _rawstor_opts.so_rcvtimeo;
}

unsigned int rawstor_opts_tcp_user_timeout(void) {
    return _rawstor_opts.tcp_user_timeout;
}

unsigned int rawstor_opts_list_limit(void) {
    return _rawstor_opts.list_limit;
}

unsigned int rawstor_opts_write_throttle_limit(void) {
    return _rawstor_opts.write_throttle_limit;
}

unsigned int rawstor_opts_write_backlog_capacity(void) {
    return _rawstor_opts.write_backlog_capacity;
}

unsigned int rawstor_opts_io_retry_backoff_base(void) {
    return _rawstor_opts.io_retry_backoff_base;
}

unsigned int rawstor_opts_io_retry_backoff_max(void) {
    return _rawstor_opts.io_retry_backoff_max;
}

unsigned int rawstor_opts_io_retry_backoff_jitter(void) {
    return _rawstor_opts.io_retry_backoff_jitter;
}

unsigned int rawstor_opts_mirror_probe_interval(void) {
    return _rawstor_opts.mirror_probe_interval;
}
