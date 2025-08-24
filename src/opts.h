#ifndef RAWSTOR_OPTS_H
#define RAWSTOR_OPTS_H

#include <rawstor.h>


// defined in rawstor.h
// struct RawstorOptsIO {
//     unsigned int wait_timeout;
// };

// defined in rawstor.h
// struct RawstorOptsOST {
//     const char *host;
//     unsigned int port;
//     unsigned int so_sndtimeo;
//     unsigned int so_rcvtimeo;
//     unsigned int tcp_user_timeout;
// };


int rawstor_opts_initialize(
    const struct RawstorOptsIO *opts_io,
    const struct RawstorOptsOST *opts_ost);

void rawstor_opts_terminate(void);

unsigned int rawstor_opts_io_wait_timtout(
    const struct RawstorOptsIO *opts_io);

const char* rawstor_opts_ost_host(
    const struct RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_port(
    const struct RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_so_sndtimeo(
    const struct RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_so_rcvtimeo(
    const struct RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_tcp_user_timeout(
    const struct RawstorOptsOST *opts_ost);


#endif  // RAWSTOR_OPTS_H
