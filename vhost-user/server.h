#ifndef _RAWSTOR_VHOST_SERVER_H_
#define _RAWSTOR_VHOST_SERVER_H_


typedef enum {
    RAWSTOR_IO_ENGINE_LIBURING
} RawstorIOEngine;


int rawstor_server(
    int object_id,
    const char *socket_path,
    RawstorIOEngine io_engine);


#endif // _RAWSTOR_VHOST_SERVER_H_
