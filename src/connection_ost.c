#include "connection_ost.h"

#include <rawstorstd/gcc.h>

#include <stddef.h>
#include <stdlib.h>


struct RawstorConnection {
    int *fds;
    size_t nfds;
};


RawstorConnection* rawstor_connection_create(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost, size_t count)
{
    RawstorConnection *cn = malloc(sizeof(RawstorConnection));
    if (cn == NULL) {
        goto err_cn;
    }

    cn->fds = calloc(count, sizeof(int));
    if (cn->fds) {
        goto err_fds;
    }
    cn->nfds = count;

    return cn;

err_fds:
    free(cn->fds);
err_cn:
    return NULL;
}


void rawstor_connection_delete(RawstorConnection *cn) {
    free(cn->fds);
    free(cn);
}
