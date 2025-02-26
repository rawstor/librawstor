#include "io.h"

#include "pool.h"

#include <aio.h>

#include <errno.h>
#include <stdlib.h>


struct RawstorIOEvent {
    struct aiocb *cbp;

    RawstorIOCallback *callback;
    void *data;
};


struct RawstorIO {
    unsigned int depth;

    RawstorPool *events_pool;
    RawstorIOEvent *events;
    struct aiocb *cbs;
    struct aiocb **cbps;
};


const char* rawstor_io_engine_name = "rt";


RawstorIO* rawstor_io_create(unsigned int depth) {
    RawstorIO *io = malloc(sizeof(RawstorIO));
    if (io == NULL) {
        return NULL;
    }

    io->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    io->cbs = calloc(depth, sizeof(struct aiocb));
    if (io->cbs == NULL) {
        free(io);
        return NULL;
    }

    io->cbps = calloc(depth, sizeof(struct aiocb*));
    if (io->cbps == NULL) {
        free(io->cbs);
        free(io);
        return NULL;
    }

    io->events_pool = rawstor_pool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        free(io->cbps);
        free(io->cbs);
        free(io);
        return NULL;
    }
    io->events = rawstor_pool_data(io->events_pool);

    for (unsigned int i = 0; i < depth; ++i) {
        io->events[i].cbp = &io->cbs[i];
        io->cbps[i] = NULL;
    }

    return io;
}


void rawstor_io_delete(RawstorIO *io) {
    rawstor_pool_delete(io->events_pool);
    free(io->cbps);
    free(io->cbs);
    free(io);
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cbp = event->cbp,
        .callback = cb,
        .data = data,
    };

    *event->cbp = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = 0,
        .aio_buf = buf,
        .aio_nbytes = size,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };


    if (aio_read(event->cbp)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    return 0;
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->cbp->aio_fildes;
}
