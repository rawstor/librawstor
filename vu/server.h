#ifndef RAWSTOR_VU_SERVER_H
#define RAWSTOR_VU_SERVER_H


#include <rawstorstd/gcc.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_vu_server(
    const char RAWSTOR_UNUSED *object_uri,
    const char *socket_path);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_VU_SERVER_H
