#include "server.h"

#include <stdio.h>


int rawstor_server(int object_id, const char *socket_path) {
    printf("object id: %d\n", object_id);
    printf("socket path: %s\n", socket_path);
    return 0;
}