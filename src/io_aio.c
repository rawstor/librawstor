#include "io.h"

#include "logging.h"
#include "mempool.h"

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
    size_t total_result;
    int error;

    void *data;
};


struct RawstorIO {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorIOEvent *events;
    struct aiocb *cbs;
    struct aiocb **cbps;
};


const char* rawstor_io_engine_name = "aio";


static int io_readv(RawstorIOEvent *event, void *data) {
    if (event->error != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->result != event->payload.iov[event->payload.index].iov_len) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(io->events_pool);

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
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_preadv(RawstorIOEvent *event, void *data) {
    if (event->error != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->result != event->payload.iov[event->payload.index].iov_len) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(io->events_pool);

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
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
        .data = io,
    };

    *next_event->cb = (struct aiocb) {
        .aio_fildes = rawstor_io_event_fd(event),
        .aio_offset = event->payload.offset + event->total_result,
        .aio_buf = event->payload.iov[event->payload.index + 1].iov_base,
        .aio_nbytes = event->payload.iov[event->payload.index + 1].iov_len,
        // .aio_reqprio
        // .aio_sigevent
        // .aio_lio_opcode
    };

    if (aio_read(next_event->cb)) {
        int errsv = errno;
        rawstor_mempool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_writev(RawstorIOEvent *event, void *data) {
    if (event->error != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->result != event->payload.iov[event->payload.index].iov_len) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(io->events_pool);

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
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static int io_pwritev(RawstorIOEvent *event, void *data) {
    if (event->error != 0) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->result != event->payload.iov[event->payload.index].iov_len) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    if (event->payload.index + 1 == event->payload.niov) {
        event->payload.callback(event, event->payload.data);
        return 0;
    }

    RawstorIO *io = (RawstorIO*)data;

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(io->events_pool);

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
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, next_event);
        errno = errsv;
        return -errno;
    }

    *next_event->cbp = next_event->cb;

    return 0;
}


static RawstorIOEvent* io_process_event(RawstorIO *io) {
    for (size_t i = 0; i < io->depth; ++i) {
        struct aiocb **cbp = &io->cbps[i];
        if (*cbp == NULL) {
            continue;
        }

        int error = aio_error(*cbp);
        if (error < 0) {
            *cbp = NULL;
            return NULL;
        }

        if (error == EINPROGRESS) {
            continue;
        }

        int result = aio_return(*cbp);
        if (result < 0) {
            *cbp = NULL;
            return NULL;
        }

        RawstorIOEvent *event = &io->events[i];
        event->error = error;
        event->result = result;
        if (result > 0) {
            event->total_result += result;
        }
        return event;
    }

    return NULL;
}


RawstorIO* rawstor_io_create(unsigned int depth) {
#ifdef AIO_LISTIO_MAX
    if (depth > AIO_LISTIO_MAX) {
        rawstor_warning(
            "Unable to create Rawstor IO buffer with depth = %d, "
            "falling back to AIO_LISTIO_MAX = %d\n",
            depth, AIO_LISTIO_MAX);
        depth = AIO_LISTIO_MAX;
    }
#endif
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

    io->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        free(io->cbps);
        free(io->cbs);
        free(io);
        return NULL;
    }
    io->events = rawstor_mempool_data(io->events_pool);

    for (unsigned int i = 0; i < depth; ++i) {
        io->events[i].cb = &io->cbs[i];
        io->events[i].cbp = &io->cbps[i];
        io->cbps[i] = NULL;
    }

    return io;
}


void rawstor_io_delete(RawstorIO *io) {
    rawstor_mempool_delete(io->events_pool);
    free(io->cbps);
    free(io->cbs);
    free(io);
}


int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

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
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

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
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
        errno = errsv;
        return -errno;
    }

    *event->cbp = event->cb;

    return 0;
}


int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    *event = (RawstorIOEvent) {
        .cb = event->cb,
        .cbp = event->cbp,
        // .payload
        .callback = cb,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

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
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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

    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

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
        .total_result = 0,
        .error = EINPROGRESS,
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
        rawstor_mempool_free(io->events_pool, event);
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

    if (rawstor_mempool_allocated(io->events_pool) == 0) {
        return NULL;
    }

    if (aio_suspend((const struct aiocb* const*)io->cbps, io->depth, NULL)) {
        return NULL;
    }

    return io_process_event(io);
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    if (rawstor_mempool_allocated(io->events_pool) == 0) {
        return NULL;
    }

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout,
    };

    if (aio_suspend((const struct aiocb* const*)io->cbps, io->depth, &ts)) {
        return NULL;
    }

    return io_process_event(io);
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
    *event->cbp = NULL;
    rawstor_mempool_free(io->events_pool, event);
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->cb->aio_fildes;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->total_result;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(event, event->data);
}
