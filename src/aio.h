#ifndef _RAWSTOR_AIO_H_
#define _RAWSTOR_AIO_H_

#include <rawstor.h>

#include <sys/types.h>

#include <stddef.h>


RawstorAIO* rawstor_aio_create(unsigned int depth);

void rawstor_aio_delete(RawstorAIO *aio);

RawstorAIOEvent* rawstor_aio_get_event(RawstorAIO *aio);

int rawstor_aio_dispatch_event(RawstorAIO *aio, RawstorAIOEvent *event);


#endif // _RAWSTOR_AIO_H_
