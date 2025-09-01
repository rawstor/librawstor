#include "connection_ost.h"

#include <stddef.h>
#include <stdlib.h>


struct RawstorConnection {
    int *fds;
};


RawstorConnection* rawstor_connection_create(void) {
    RawstorConnection *cn = malloc(sizeof(RawstorConnection));
    if (cn == NULL) {
        goto err_cn;
    }

    return cn;

err_cn:
    return NULL;
}


void rawstor_connection_delete(RawstorConnection *cn) {
    free(cn);
}
