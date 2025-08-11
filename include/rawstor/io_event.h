#ifndef RAWSTOR_IO_EVENT_H
#define RAWSTOR_IO_EVENT_H

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOEvent RawstorIOEvent;


int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_IO_EVENT_H
