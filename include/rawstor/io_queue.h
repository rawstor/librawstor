#ifndef RAWSTOR_IO_QUEUE_H
#define RAWSTOR_IO_QUEUE_H

#include <rawstor/io_event.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_IO_QUEUE_H
