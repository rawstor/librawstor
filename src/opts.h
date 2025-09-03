#ifndef RAWSTOR_OPTS_H
#define RAWSTOR_OPTS_H

#include <rawstor.h>


#ifdef __cplusplus
extern "C" {
#endif


// defined in rawstor.h
// struct RawstorOpts {
//     unsigned int wait_timeout;
//     unsigned int so_sndtimeo;
//     unsigned int so_rcvtimeo;
//     unsigned int tcp_user_timeout;
// };


int rawstor_opts_initialize(const struct RawstorOpts *opts);

void rawstor_opts_terminate(void);

unsigned int rawstor_opts_wait_timeout(void);

unsigned int rawstor_opts_so_sndtimeo(void);

unsigned int rawstor_opts_so_rcvtimeo(void);

unsigned int rawstor_opts_tcp_user_timeout(void);


#ifdef __cplusplus
}
#endif


#endif  // RAWSTOR_OPTS_H
