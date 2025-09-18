#include "opts.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define RAWSTOR_OPTS_WAIT_TIMEOUT 5000
#define RAWSTOR_OPTS_SESSIONS 1
#define RAWSTOR_OPTS_SO_SNDTIMEO 5000
#define RAWSTOR_OPTS_SO_RCVTIMEO 5000
#define RAWSTOR_OPTS_TCP_USER_TIMEOUT 5000


static struct RawstorOpts _rawstor_opts = {};


static int get_env_int(const char *name, int def) {
    const char *strval = getenv(name);
    if (strval == NULL) {
        return def;
    }

    int intval;
    if (sscanf(strval, "%d", &intval) != 1) {
        return def;
    }

    return intval;
}


int rawstor_opts_initialize(const struct RawstorOpts *opts) {
    _rawstor_opts.wait_timeout =
        (opts != NULL && opts->wait_timeout != 0) ?
        opts->wait_timeout : get_env_int(
            "RAWSTOR_OPTS_WAIT_TIMEOUT",
            RAWSTOR_OPTS_WAIT_TIMEOUT);

    _rawstor_opts.sessions =
        (opts != NULL && opts->sessions != 0) ?
        opts->sessions : get_env_int(
            "RAWSTOR_OPTS_SESSIONS",
            RAWSTOR_OPTS_SESSIONS);

    _rawstor_opts.so_sndtimeo =
        (opts != NULL && opts->so_sndtimeo != 0) ?
        opts->so_sndtimeo : get_env_int(
            "RAWSTOR_OPTS_SO_SNDTIMEO",
            RAWSTOR_OPTS_SO_SNDTIMEO);

    _rawstor_opts.so_rcvtimeo =
        (opts != NULL && opts->so_rcvtimeo != 0) ?
        opts->so_rcvtimeo : get_env_int(
            "RAWSTOR_OPTS_SO_RCVTIMEO",
            RAWSTOR_OPTS_SO_RCVTIMEO);

    _rawstor_opts.tcp_user_timeout =
        (opts != NULL && opts->tcp_user_timeout != 0) ?
        opts->tcp_user_timeout : get_env_int(
            "RAWSTOR_OPTS_TCP_USER_TIMEOUT",
            RAWSTOR_OPTS_TCP_USER_TIMEOUT);

    return 0;
}


void rawstor_opts_terminate(void) {
    /**
     * Free opts here.
     */
}


unsigned int rawstor_opts_wait_timeout(void) {
    return _rawstor_opts.wait_timeout;
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
