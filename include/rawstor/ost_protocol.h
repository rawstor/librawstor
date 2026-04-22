#ifndef RAWSTOR_OST_PROTOCOL_H
#define RAWSTOR_OST_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAWSTOR_PACKED __attribute__((packed))

#define RAWSTOR_MAGIC 0x72737472 // "rstr" as ascii

enum RawstorOSTCommandType {
    RAWSTOR_CMD_SET_OBJECT,
    RAWSTOR_CMD_READ,
    RAWSTOR_CMD_WRITE,
    RAWSTOR_CMD_DISCARD,
};

struct RawstorOSTFrameHead {
    uint32_t magic;
    enum RawstorOSTCommandType cmd;
} RAWSTOR_PACKED;

/* Minimalistic protocol frame */
struct RawstorOSTFrameBasicBody {
    // var is for minimal commands only,
    // will be overridden in other command structs
    uint8_t obj_id[16];
    uint64_t offset;
    uint64_t val;
} RAWSTOR_PACKED;

struct RawstorOSTFrameBasic {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameBasicBody body;
} RAWSTOR_PACKED;

struct RawstorOSTFrameIOBody {
    uint16_t cid;
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    bool sync;
} RAWSTOR_PACKED;

struct RawstorOSTFrameIO {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameIOBody body;
} RAWSTOR_PACKED;

/* response frames */
struct RawstorOSTFrameResponse {
    struct RawstorOSTFrameHead head;
    uint16_t cid;
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
    uint64_t hash;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OST_PROTOCOL_H
