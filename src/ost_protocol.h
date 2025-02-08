#ifndef RAWSTOR_OST_PROTOCOL_H
#define RAWSTOR_OST_PROTOCOL_H

#include "gcc.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>


#define MIN_CMD_VAR_LEN 32


typedef enum {
    RAWSTOR_CMD_SET_OBJECT,
    RAWSTOR_CMD_READ,
    RAWSTOR_CMD_WRITE,
    RAWSTOR_CMD_DISCARD,
} RawstorOSTCommandType;


/* Just for basic validation only */
typedef struct {
    RawstorOSTCommandType cmd;
} RAWSTOR_PACKED RawstorOSTFrameCmdOnly;


/* Minimalistic protocol frame */
typedef struct {
    RawstorOSTCommandType cmd;
    // var is for minimal commands only,
    // will be overridden in other command structs
    char var[MIN_CMD_VAR_LEN];
} RAWSTOR_PACKED RawstorOSTFrameBasic;


typedef struct {
    RawstorOSTCommandType cmd;
    u_int64_t offset;
    u_int32_t len;
    bool sync;
} RAWSTOR_PACKED RawstorOSTFrameIO;


/* response frames */
typedef struct {
    RawstorOSTCommandType cmd;
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
} RAWSTOR_PACKED RawstorOSTFrameResponse;


#endif // RAWSTOR_OST_PROTOCOL_H
