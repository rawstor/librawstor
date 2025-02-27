#include "io.h"

#include "pool.h"

#include <aio.h>

#include <errno.h>
#include <stdlib.h>


struct RawstorIOEvent {
    struct aiocb *cb;
    struct aiocb **cbp;

    RawstorIOCallback *callback;

    ssize_t res;

    void *data;
};


struct RawstorIO {
    unsigned int depth;

    RawstorPool *events_pool;
    RawstorIOEvent *events;
    struct aiocb *cbs;
    struct aiocb **cbps;
};


const char* rawstor_io_engine_name = "aio";


static RawstorIOEvent* io_process_event(RawstorIO *io) {
    for (size_t i = 0; i < io->depth; ++i) {
        struct aiocb **cbp = &io->cbps[i];
        if (cbp == NULL) {
            continue;
        }

        int err = aio_error(*cbp);
        if (err < 0) {
            /**
             * FIXME: This will hide err.
             */
            *cbp = NULL;
            continue;
        }

        if (err == EINPROGRESS) {
            continue;
        }

        RawstorIOEvent *event = &io->events[i];

        if (err == 0) {
            int res = aio_return(*cbp);
            if (res < 0) {
                /**
                 * FIXME: This will hide err in res.
                 */
                *cbp = NULL;
                continue;
            }
            event->res = res;
        } else {
            event->res = -err;
        }

        return event;
    }

    return NULL;
}


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
        io->events[i].cb = &io->cbs[i];
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
        .cb = event->cb,
        .cbp = event->cbp,
        .callback = cb,
        // .res
        .data = data,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = 0,
        .aio_buf = buf,
        .aio_nbytes = size,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_read(event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        .callback = cb,
        // .res
        .data = data,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = offset,
        .aio_buf = buf,
        .aio_nbytes = size,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_read(event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io) {
    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    if (aio_suspend((const struct aiocb* const*)io->cbps, io->depth, NULL)) {
        return NULL;
    }

    return io_process_event(io);
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
    *event->cbp = NULL;
    rawstor_pool_free(io->events_pool, event);
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->cb->aio_fildes;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(
        event, event->cb->aio_nbytes, event->res, event->data);
}
