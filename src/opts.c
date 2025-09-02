#include "opts.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define RAWSTOR_OPTS_WAIT_TIMEOUT 5000
#define RAWSTOR_OPTS_SO_SNDTIMEO 5000
#define RAWSTOR_OPTS_SO_RCVTIMEO 5000
#define RAWSTOR_OPTS_TCP_USER_TIMEOUT 5000

#define RAWSTOR_OPTS_OST_HOST "127.0.0.1"
#define RAWSTOR_OPTS_OST_PORT 8080


static struct RawstorOpts _rawstor_opts = {};

static struct RawstorOptsOST _rawstor_opts_ost = {};


static char* opts_string(const char *value, const char *default_value) {
    const char *src = value != NULL ? value : default_value;
    assert(src != NULL);

    return strdup(src);
}


int rawstor_opts_initialize(
    const struct RawstorOpts *opts,
    const struct RawstorOptsOST *opts_ost)
{
    _rawstor_opts.wait_timeout =
        (opts != NULL && opts->wait_timeout != 0) ?
        opts->wait_timeout : RAWSTOR_OPTS_WAIT_TIMEOUT;

    _rawstor_opts.so_sndtimeo =
        (opts != NULL && opts->so_sndtimeo != 0) ?
        opts->so_sndtimeo : RAWSTOR_OPTS_SO_SNDTIMEO;

    _rawstor_opts.so_rcvtimeo =
        (opts != NULL && opts->so_rcvtimeo != 0) ?
        opts->so_rcvtimeo : RAWSTOR_OPTS_SO_RCVTIMEO;

    _rawstor_opts.tcp_user_timeout =
        (opts != NULL && opts->tcp_user_timeout != 0) ?
        opts->tcp_user_timeout : RAWSTOR_OPTS_TCP_USER_TIMEOUT;

    _rawstor_opts_ost.host = opts_string(
        opts_ost != NULL ? opts_ost->host : NULL, RAWSTOR_OPTS_OST_HOST);
    if (_rawstor_opts_ost.host == NULL) {
        return -errno;
    }

    _rawstor_opts_ost.port = (opts_ost != NULL && opts_ost->port != 0) ?
        opts_ost->port : RAWSTOR_OPTS_OST_PORT;

    return 0;
}


void rawstor_opts_terminate(void) {
    free(_rawstor_opts_ost.host);
}


unsigned int rawstor_opts_wait_timeout(const struct RawstorOpts *opts) {
    if (opts != NULL && opts->wait_timeout != 0) {
        return opts->wait_timeout;
    }
    return _rawstor_opts.wait_timeout;
}


unsigned int rawstor_opts_ost_so_sndtimeo(const struct RawstorOpts *opts) {
    if (opts != NULL && opts->so_sndtimeo != 0) {
        return opts->so_sndtimeo;
    }
    return _rawstor_opts.so_sndtimeo;
}


unsigned int rawstor_opts_so_rcvtimeo(const struct RawstorOpts *opts) {
    if (opts != NULL && opts->so_rcvtimeo != 0) {
        return opts->so_rcvtimeo;
    }
    return _rawstor_opts.so_rcvtimeo;
}


unsigned int rawstor_opts_tcp_user_timeout(const struct RawstorOpts *opts) {
    if (opts != NULL && opts->tcp_user_timeout != 0) {
        return opts->tcp_user_timeout;
    }
    return _rawstor_opts.tcp_user_timeout;
}


const char* rawstor_opts_ost_host(const struct RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->host != NULL) {
        return opts_ost->host;
    }
    return _rawstor_opts_ost.host;
}


unsigned int rawstor_opts_ost_port(const struct RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->port != 0) {
        return opts_ost->port;
    }
    return _rawstor_opts_ost.port;
}
