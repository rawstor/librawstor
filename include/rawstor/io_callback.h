#ifndef RAWSTOR_IO_CALLBACK_H
#define RAWSTOR_IO_CALLBACK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int(RawstorIOCallback)(size_t result, int error, void* data);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_IO_CALLBACK_H
