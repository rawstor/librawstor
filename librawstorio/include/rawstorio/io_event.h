#ifndef RAWSTORIO_IO_EVENT_H
#define RAWSTORIO_IO_EVENT_H

#include <rawstor.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


// defined in rawstor.h
// typedef struct RawstorIOEvent RawstorIOEvent;


int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);

int rawstor_io_event_dispatch(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_IO_EVENT_H
