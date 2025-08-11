#ifndef RAWSTORIO_EVENT_H
#define RAWSTORIO_EVENT_H

#include <rawstor.h>

#include <stddef.h>


// defined in rawstor.h
// typedef struct RawstorIOEvent RawstorIOEvent;


int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);

int rawstor_io_event_dispatch(RawstorIOEvent *event);


#endif // RAWSTORIO_IO_H
