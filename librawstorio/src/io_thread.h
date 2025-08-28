#ifndef RAWSTORIO_IO_THREAD_H
#define RAWSTORIO_IO_THREAD_H

#include <rawstorio/io.h>
#include <rawstorio/io_event.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_io_push_cqe(RawstorIO *io, RawstorIOEvent *event);

int rawstor_io_push_cqes(
    RawstorIO *io, RawstorIOEvent **events, size_t nevents);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_IO_THREAD_H
