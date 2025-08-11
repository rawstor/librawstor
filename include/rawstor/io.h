#ifndef RAWSTOR_IO_H
#define RAWSTOR_IO_H

#include <rawstor/io_event.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_EVENT_H
