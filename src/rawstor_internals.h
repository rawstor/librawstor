#ifndef RAWSTOR_INTERNALS_H
#define RAWSTOR_INTERNALS_H

#include <rawstor.h>


#ifdef __cplusplus
extern "C" {
#endif


extern RawstorIOQueue *rawstor_io_queue;

const struct RawstorSocketAddress* rawstor_default_ost(void);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_INTERNALS_H
