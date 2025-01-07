#include <stdbool.h>
#include <arpa/inet.h>
#include "stdint.h"

#define MIN_CMD_VAR_LEN 32

typedef enum {
  CMD_SET_OBJECT,
  CMD_READ,
  CMD_WRITE,
  CMD_DISCARD,
} commands_t;

/* minimalistic protocol frame */
typedef struct {
  commands_t cmd;
  // var is for minimal commands only, will be overridden in other command structs
  char var[MIN_CMD_VAR_LEN];
}__attribute__((packed)) proto_basic_frame_t;

typedef struct {
  commands_t cmd;
  u_int64_t offset;
  u_int64_t len;
}__attribute__((packed)) proto_io_frame_t;

typedef struct {
  commands_t cmd;
  u_int64_t offset;
  u_int64_t len;
  bool sync;
}__attribute__((packed)) proto_io_w_frame_t;

/* response frames */
typedef struct {
  commands_t cmd;
  int16_t res;
}__attribute__((packed)) proto_resp_frame_t;
