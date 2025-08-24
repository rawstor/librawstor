#include "opts.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define RAWSTOR_OPTS_IO_WAIT_TIMEOUT 5000

#define RAWSTOR_OPTS_OST_HOST "127.0.0.1"
#define RAWSTOR_OPTS_OST_PORT 8080
#define RAWSTOR_OPTS_OST_SO_SNDTIMEO 5000
#define RAWSTOR_OPTS_OST_SO_RCVTIMEO 5000
#define RAWSTOR_OPTS_OST_TCP_USER_TIMEOUT 5000


static struct RawstorOptsIO _rawstor_opts_io = {};

static struct RawstorOptsOST _rawstor_opts_ost = {};


static char* opts_string(const char *value, const char *default_value) {
    const char *src = value != NULL ? value : default_value;
    assert(src != NULL);

    return strdup(src);
}


int rawstor_opts_initialize(
    const struct RawstorOptsIO *opts_io,
    const struct RawstorOptsOST *opts_ost)
{
    _rawstor_opts_io.wait_timeout =
        (opts_io != NULL && opts_io->wait_timeout != 0) ?
        opts_io->wait_timeout : RAWSTOR_OPTS_IO_WAIT_TIMEOUT;

    _rawstor_opts_ost.host = opts_string(
        opts_ost != NULL ? opts_ost->host : NULL, RAWSTOR_OPTS_OST_HOST);
    if (_rawstor_opts_ost.host == NULL) {
        return -errno;
    }

    _rawstor_opts_ost.port = (opts_ost != NULL && opts_ost->port != 0) ?
        opts_ost->port : RAWSTOR_OPTS_OST_PORT;

    _rawstor_opts_ost.so_sndtimeo =
        (opts_ost != NULL && opts_ost->so_sndtimeo != 0) ?
        opts_ost->so_sndtimeo : RAWSTOR_OPTS_OST_SO_SNDTIMEO;

    _rawstor_opts_ost.so_rcvtimeo =
        (opts_ost != NULL && opts_ost->so_rcvtimeo != 0) ?
        opts_ost->so_rcvtimeo : RAWSTOR_OPTS_OST_SO_RCVTIMEO;

    _rawstor_opts_ost.tcp_user_timeout =
        (opts_ost != NULL && opts_ost->tcp_user_timeout != 0) ?
        opts_ost->tcp_user_timeout : RAWSTOR_OPTS_OST_TCP_USER_TIMEOUT;

    return 0;
}


void rawstor_opts_terminate(void) {
    free(_rawstor_opts_ost.host);
}


unsigned int rawstor_opts_io_wait_timeout(
    const struct RawstorOptsIO *opts_io)
{
    if (opts_io != NULL && opts_io->wait_timeout != 0) {
        return opts_io->wait_timeout;
    }
    return _rawstor_opts_io.wait_timeout;
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


unsigned int rawstor_opts_ost_so_sndtimeo(const struct RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->so_sndtimeo != 0) {
        return opts_ost->so_sndtimeo;
    }
    return _rawstor_opts_ost.so_sndtimeo;
}


unsigned int rawstor_opts_ost_so_rcvtimeo(const struct RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->so_rcvtimeo != 0) {
        return opts_ost->so_rcvtimeo;
    }
    return _rawstor_opts_ost.so_rcvtimeo;
}


unsigned int rawstor_opts_ost_tcp_user_timeout(const struct RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->tcp_user_timeout != 0) {
        return opts_ost->tcp_user_timeout;
    }
    return _rawstor_opts_ost.tcp_user_timeout;
}
