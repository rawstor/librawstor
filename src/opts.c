#include "opts.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define RAWSTOR_OPTS_IO_ATTEMPTS 3
#define RAWSTOR_OPTS_SESSIONS 1
#define RAWSTOR_OPTS_SO_SNDTIMEO 5000
#define RAWSTOR_OPTS_SO_RCVTIMEO 5000
#define RAWSTOR_OPTS_TCP_USER_TIMEOUT 5000
#define RAWSTOR_OPTS_LIST_LIMIT 1000
#define RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT 128
#define RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY (256u * 1024 * 1024)

static struct RawstorOpts _rawstor_opts = {};

static unsigned int get_env_uint(const char* name, int def) {
    const char* strval = getenv(name);
    if (strval == NULL) {
        return def;
    }

    unsigned int uintval;
    if (sscanf(strval, "%u", &uintval) != 1) {
        return def;
    }

    return uintval;
}

int rawstor_opts_initialize(const struct RawstorOpts* opts) {
    _rawstor_opts.io_attempts =
        (opts != NULL && opts->io_attempts != 0)
            ? opts->io_attempts
            : get_env_uint(
                  "RAWSTOR_OPTS_IO_ATTEMPTS", RAWSTOR_OPTS_IO_ATTEMPTS
              );

    _rawstor_opts.sessions =
        (opts != NULL && opts->sessions != 0)
            ? opts->sessions
            : get_env_uint("RAWSTOR_OPTS_SESSIONS", RAWSTOR_OPTS_SESSIONS);

    _rawstor_opts.so_sndtimeo =
        (opts != NULL && opts->so_sndtimeo != 0)
            ? opts->so_sndtimeo
            : get_env_uint(
                  "RAWSTOR_OPTS_SO_SNDTIMEO", RAWSTOR_OPTS_SO_SNDTIMEO
              );

    _rawstor_opts.so_rcvtimeo =
        (opts != NULL && opts->so_rcvtimeo != 0)
            ? opts->so_rcvtimeo
            : get_env_uint(
                  "RAWSTOR_OPTS_SO_RCVTIMEO", RAWSTOR_OPTS_SO_RCVTIMEO
              );

    _rawstor_opts.tcp_user_timeout =
        (opts != NULL && opts->tcp_user_timeout != 0)
            ? opts->tcp_user_timeout
            : get_env_uint(
                  "RAWSTOR_OPTS_TCP_USER_TIMEOUT", RAWSTOR_OPTS_TCP_USER_TIMEOUT
              );

    _rawstor_opts.list_limit =
        (opts != NULL && opts->list_limit != 0)
            ? opts->list_limit
            : get_env_uint("RAWSTOR_OPTS_LIST_LIMIT", RAWSTOR_OPTS_LIST_LIMIT);

    _rawstor_opts.write_throttle_limit =
        (opts != NULL && opts->write_throttle_limit != 0)
            ? opts->write_throttle_limit
            : get_env_uint(
                  "RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT",
                  RAWSTOR_OPTS_WRITE_THROTTLE_LIMIT
              );

    _rawstor_opts.write_backlog_capacity =
        (opts != NULL && opts->write_backlog_capacity != 0)
            ? opts->write_backlog_capacity
            : get_env_uint(
                  "RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY",
                  RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY
              );

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
