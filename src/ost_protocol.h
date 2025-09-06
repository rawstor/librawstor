#ifndef RAWSTOR_OST_PROTOCOL_H
#define RAWSTOR_OST_PROTOCOL_H

#include <rawstorstd/gcc.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


#define RAWSTOR_MAGIC 0x72737472 // "rstr" as ascii


typedef enum {
    RAWSTOR_CMD_SET_OBJECT,
    RAWSTOR_CMD_READ,
    RAWSTOR_CMD_WRITE,
    RAWSTOR_CMD_DISCARD,
} RawstorOSTCommandType;


/* Just for basic validation only */
typedef struct {
    uint32_t magic;
    RawstorOSTCommandType cmd;
} RAWSTOR_PACKED RawstorOSTFrameCmdOnly;


/* Minimalistic protocol frame */
typedef struct {
    uint32_t magic;
    RawstorOSTCommandType cmd;
    // var is for minimal commands only,
    // will be overridden in other command structs
    uint8_t obj_id[16];
    uint64_t offset;
    uint64_t val;
} RAWSTOR_PACKED RawstorOSTFrameBasic;


typedef struct {
    uint32_t magic;
    RawstorOSTCommandType cmd;
    uint16_t cid;
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    bool sync;
} RAWSTOR_PACKED RawstorOSTFrameIO;


/* response frames */
typedef struct {
    uint32_t magic;
    RawstorOSTCommandType cmd;
    uint16_t cid;
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
    uint64_t hash;
} RAWSTOR_PACKED RawstorOSTFrameResponse;


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_OST_PROTOCOL_H
