#ifndef RAWSTOR_OPTS_H
#define RAWSTOR_OPTS_H

#include <rawstor.h>


// defined in rawstor.h
// typedef struct {
//     const char *host;
//     unsigned int port;
//     unsigned int so_sndtimeo;
//     unsigned int so_rcvtimeo;
//     unsigned int tcp_user_timeout;
// } RawstorOptsOST;


int rawstor_opts_initialize(const RawstorOptsOST *opts_ost);

void rawstor_opts_terminate(void);

const char* rawstor_opts_ost_host(const RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_port(const RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_so_sndtimeo(const RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_so_rcvtimeo(const RawstorOptsOST *opts_ost);

unsigned int rawstor_opts_ost_tcp_user_timeout(const RawstorOptsOST *opts_ost);


#endif  // RAWSTOR_OPTS_H
