#ifndef LIBRAWSTOR_IO_H
#define LIBRAWSTOR_IO_H

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOEvent RawstorIOEvent;

typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // LIBRAWSTOR_RAWSTOR_H
