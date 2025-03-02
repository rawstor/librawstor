#include "io.h"

#include "pool.h"

#include <aio.h>

#include <errno.h>
#include <stdlib.h>


struct RawstorIOEvent {
    struct aiocb *cb;
    struct aiocb **cbp;

    struct {
        unsigned int index;
        struct iovec *iov;
        unsigned int niov;
        off_t offset;
        RawstorIOCallback *callback;
        void *data;
    } payload;

    RawstorIOCallback *callback;

    size_t size;
    size_t result;

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


static int io_readv(RawstorIOEvent *event, void *data) {
    if (rawstor_io_event_error(event) != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if ((size_t)aio_return(event->cb) != 
        event->payload.iov[event->payload.index].iov_len)
    {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_pool_alloc(io->events_pool);

    *next_event = (RawstorIOEvent) {
        .cb = next_event->cb,
        .cbp = next_event->cbp,
        .payload = {
            .index = event->payload.index + 1,
            .iov = event->payload.iov,
            .niov = event->payload.niov,
            .offset = 0,
            .callback = event->payload.callback,
            .data = event->payload.data,
        },
        .callback = io_readv,
        .size = rawstor_io_event_size(event),
        .result = event->result,
        .data = io,
    };

    *next_event->cb = (struct aiocb) {
        .aio_fildes = rawstor_io_event_fd(event),
        .aio_offset = 0,
        .aio_buf = event->payload.iov[event->payload.index + 1].iov_base,
        .aio_nbytes = event->payload.iov[event->payload.index + 1].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_read(next_event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_preadv(RawstorIOEvent *event, void *data) {
    if (rawstor_io_event_error(event) != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if ((size_t)aio_return(event->cb) != 
        event->payload.iov[event->payload.index].iov_len)
    {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_pool_alloc(io->events_pool);

    *next_event = (RawstorIOEvent) {
        .cb = next_event->cb,
        .cbp = next_event->cbp,
        .payload = {
            .index = event->payload.index + 1,
            .iov = event->payload.iov,
            .niov = event->payload.niov,
            .offset = event->payload.offset,
            .callback = event->payload.callback,
            .data = event->payload.data,
        },
        .callback = io_readv,
        .size = rawstor_io_event_size(event),
        .result = event->result,
        .data = io,
    };

    *next_event->cb = (struct aiocb) {
        .aio_fildes = rawstor_io_event_fd(event),
        .aio_offset = event->payload.offset + event->result,
        .aio_buf = event->payload.iov[event->payload.index + 1].iov_base,
        .aio_nbytes = event->payload.iov[event->payload.index + 1].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_read(next_event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_writev(RawstorIOEvent *event, void *data) {
    if (rawstor_io_event_error(event) != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if ((size_t)aio_return(event->cb) != 
        event->payload.iov[event->payload.index].iov_len)
    {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_pool_alloc(io->events_pool);

    *next_event = (RawstorIOEvent) {
        .cb = next_event->cb,
        .cbp = next_event->cbp,
        .payload = {
            .index = event->payload.index + 1,
            .iov = event->payload.iov,
            .niov = event->payload.niov,
            .offset = 0,
            .callback = event->payload.callback,
            .data = event->payload.data,
        },
        .callback = io_writev,
        .size = rawstor_io_event_size(event),
        .result = event->result,
        .data = io,
    };

    *next_event->cb = (struct aiocb) {
        .aio_fildes = rawstor_io_event_fd(event),
        .aio_offset = 0,
        .aio_buf = event->payload.iov[event->payload.index + 1].iov_base,
        .aio_nbytes = event->payload.iov[event->payload.index + 1].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_write(next_event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_pwritev(RawstorIOEvent *event, void *data) {
    if (rawstor_io_event_error(event) != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if ((size_t)aio_return(event->cb) != 
        event->payload.iov[event->payload.index].iov_len)
    {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_pool_alloc(io->events_pool);

    *next_event = (RawstorIOEvent) {
        .cb = next_event->cb,
        .cbp = next_event->cbp,
        .payload = {
            .index = event->payload.index + 1,
            .iov = event->payload.iov,
            .niov = event->payload.niov,
            .offset = event->payload.offset,
            .callback = event->payload.callback,
            .data = event->payload.data,
        },
        .callback = io_writev,
        .size = rawstor_io_event_size(event),
        .result = event->result,
        .data = io,
    };

    *next_event->cb = (struct aiocb) {
        .aio_fildes = rawstor_io_event_fd(event),
        .aio_offset = event->payload.offset + event->result,
        .aio_buf = event->payload.iov[event->payload.index + 1].iov_base,
        .aio_nbytes = event->payload.iov[event->payload.index + 1].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_write(next_event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


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
            event->result += aio_return(*cbp);
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
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
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
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
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


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        .payload = {
            .index = 0,
            .iov = iov,
            .niov = niov,
            .offset = 0,
            .callback = cb,
            .data = data,
        },
        .callback = io_readv,
        .size = size,
        .result = 0,
        .data = io,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = 0,
        .aio_buf = iov[0].iov_base,
        .aio_nbytes = iov[0].iov_len,
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


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        .payload = {
            .index = 0,
            .iov = iov,
            .niov = niov,
            .offset = offset,
            .callback = cb,
            .data = data,
        },
        .callback = io_preadv,
        .size = size,
        .result = 0,
        .data = io,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = offset,
        .aio_buf = iov[0].iov_base,
        .aio_nbytes = iov[0].iov_len,
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


int rawstor_io_recv(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_read(io, fd, buf, size, cb, data);
}


int rawstor_io_recvv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_readv(io, fd, iov, niov, size, cb, data);
}


int rawstor_io_write(
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
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
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

    if (aio_write(event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


int rawstor_io_pwrite(
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
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
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

    if (aio_write(event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        .payload = {
            .index = 0,
            .iov = iov,
            .niov = niov,
            .offset = 0,
            .callback = cb,
            .data = data,
        },
        .callback = io_writev,
        .size = size,
        .result = 0,
        .data = io,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = 0,
        .aio_buf = iov[0].iov_base,
        .aio_nbytes = iov[0].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_write(event->cb)) {
        int errsv = errno;
        rawstor_pool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_pool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_pool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        .payload = {
            .index = 0,
            .iov = iov,
            .niov = niov,
            .offset = offset,
            .callback = cb,
            .data = data,
        },
        .callback = io_pwritev,
        .size = size,
        .result = 0,
        .data = io,
    };

    *event->cb = (struct aiocb) {
        .aio_fildes = fd,
        .aio_offset = offset,
        .aio_buf = iov[0].iov_base,
        .aio_nbytes = iov[0].iov_len,
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


int rawstor_io_send(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_write(io, fd, buf, size, cb, data);
}


int rawstor_io_sendv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_writev(io, fd, iov, niov, size, cb, data);
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


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout,
    };

    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    if (aio_suspend((const struct aiocb* const*)io->cbps, io->depth, &ts)) {
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


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return aio_error(event->cb);
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(event, event->data);
}
