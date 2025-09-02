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

// defined in rawstor.h
// struct RawstorOptsOST {
//     char *host;
//     unsigned int port;
// };


int rawstor_opts_initialize(
    const struct RawstorOpts *opts,
    const struct RawstorOptsOST *opts_ost);

void rawstor_opts_terminate(void);

unsigned int rawstor_opts_wait_timeout(const struct RawstorOpts *opts);

unsigned int rawstor_opts_so_sndtimeo(const struct RawstorOpts *opts);

unsigned int rawstor_opts_so_rcvtimeo(const struct RawstorOpts *opts);

unsigned int rawstor_opts_tcp_user_timeout(const struct RawstorOpts *opts);

const char* rawstor_opts_ost_host(const struct RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_port(const struct RawstorOptsOST *opts_ost);


#ifdef __cplusplus
}
#endif


#endif  // RAWSTOR_OPTS_H
