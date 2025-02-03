#ifndef RAWSTOR_OST_PROTOCOL_H
#define RAWSTOR_OST_PROTOCOL_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>


#define OST_PACKED __attribute__((packed))

#define MIN_CMD_VAR_LEN 32


typedef enum {
    CMD_SET_OBJECT,
    CMD_READ,
    CMD_WRITE,
    CMD_DISCARD,
} commands_t;


/* Just for basic validation only */
typedef struct {
    commands_t cmd;
} OST_PACKED proto_cmdonly_frame_t;


/* Minimalistic protocol frame */
typedef struct {
    commands_t cmd;
    // var is for minimal commands only, will be overridden in other command structs
    char var[MIN_CMD_VAR_LEN];
} OST_PACKED proto_basic_frame_t;


typedef struct {
    commands_t cmd;
    u_int64_t offset;
    u_int32_t len;
    bool sync;
} OST_PACKED proto_io_frame_t;


/* response frames */
typedef struct {
    commands_t cmd;
    // TODO: if we send length in res - it should be the same type (signed-unsigned too)
    int32_t res;
} OST_PACKED proto_resp_frame_t;


#endif // RAWSTOR_OST_PROTOCOL_H
