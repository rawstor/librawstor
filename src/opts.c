#include "opts.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


static RawstorOptsOST _rawstor_opts_ost = {};


static char* opts_string(const char *value, const char *default_value) {
    const char *src = value != NULL ? value : default_value;
    assert(src != NULL);

    return strdup(src);
}


int rawstor_opts_initialize(const RawstorOptsOST *opts_ost) {
    _rawstor_opts_ost.host = opts_string(
        opts_ost != NULL ? opts_ost->host : NULL, "127.0.0.1");
    if (_rawstor_opts_ost.host == NULL) {
        return -errno;
    }

    _rawstor_opts_ost.port = (opts_ost != NULL && opts_ost->port != 0) ?
        opts_ost->port : 8080;

    _rawstor_opts_ost.so_sndtimeo =
        (opts_ost != NULL && opts_ost->so_sndtimeo != 0) ?
        opts_ost->so_sndtimeo : 5000;

    _rawstor_opts_ost.so_rcvtimeo =
        (opts_ost != NULL && opts_ost->so_rcvtimeo != 0) ?
        opts_ost->so_rcvtimeo : 5000;

    return 0;
}


void rawstor_opts_terminate(void) {
    free(_rawstor_opts_ost.host);
}


const char* rawstor_opts_ost_host(const RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->host != NULL) {
        return opts_ost->host;
    }
    return _rawstor_opts_ost.host;
}


unsigned int rawstor_opts_ost_port(const RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->port != 0) {
        return opts_ost->port;
    }
    return _rawstor_opts_ost.port;
}


unsigned int rawstor_opts_ost_so_sndtimeo(const RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->so_sndtimeo != 0) {
        return opts_ost->so_sndtimeo;
    }
    return _rawstor_opts_ost.so_sndtimeo;
}


unsigned int rawstor_opts_ost_so_rcvtimeo(const RawstorOptsOST *opts_ost) {
    if (opts_ost != NULL && opts_ost->so_rcvtimeo != 0) {
        return opts_ost->so_rcvtimeo;
    }
    return _rawstor_opts_ost.so_rcvtimeo;
}
