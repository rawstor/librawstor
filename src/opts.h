#ifndef RAWSTOR_OPTS_H
#define RAWSTOR_OPTS_H

#include <rawstor.h>

#ifdef __cplusplus
extern "C" {
#endif

// defined in rawstor.h
// struct RawstorOpts {
//     unsigned int io_attempts;
//     unsigned int sessions;
//     unsigned int so_sndtimeo;
//     unsigned int so_rcvtimeo;
//     unsigned int tcp_user_timeout;
//     unsigned int list_limit;
//     unsigned int write_throttle_limit;
//     unsigned int write_backlog_capacity;
// };

int rawstor_opts_initialize(const struct RawstorOpts* opts);

void rawstor_opts_terminate(void);

unsigned int rawstor_opts_io_attempts(void);

unsigned int rawstor_opts_sessions(void);

unsigned int rawstor_opts_so_sndtimeo(void);

unsigned int rawstor_opts_so_rcvtimeo(void);

unsigned int rawstor_opts_tcp_user_timeout(void);

unsigned int rawstor_opts_list_limit(void);

unsigned int rawstor_opts_write_throttle_limit(void);

unsigned int rawstor_opts_write_backlog_capacity(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OPTS_H
