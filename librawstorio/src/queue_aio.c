#include "rawstorio/queue.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>

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


struct RawstorIOQueue {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorIOEvent *events;
    struct aiocb *cbs;
    struct aiocb **cbps;
};


static int io_event_readv(RawstorIOEvent *event, void *data) {
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

    RawstorIOQueue *queue = (RawstorIOQueue*)data;

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_readv,
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_read;
    }

    *next_event->cbp = next_event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, next_event);
    return -errno;
}


static int io_event_preadv(RawstorIOEvent *event, void *data) {
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

    RawstorIOQueue *queue = (RawstorIOQueue*)data;

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_readv,
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_read;
    }

    *next_event->cbp = next_event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, next_event);
    return -errno;
}


static int io_event_writev(RawstorIOEvent *event, void *data) {
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

    RawstorIOQueue *queue = (RawstorIOQueue*)data;

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_writev,
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_write;
    }

    *next_event->cbp = next_event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, next_event);
    return -errno;
}


static int io_event_pwritev(RawstorIOEvent *event, void *data) {
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

    RawstorIOQueue *queue = (RawstorIOQueue*)data;

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *next_event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_writev,
        .size = event->size,
        .result = 0,
        .total_result = event->total_result,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_write;
    }

    *next_event->cbp = next_event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, next_event);
    return -errno;
}


static RawstorIOEvent* io_process_event(RawstorIOQueue *queue) {
    for (size_t i = 0; i < queue->depth; ++i) {
        struct aiocb **cbp = &queue->cbps[i];
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

        RawstorIOEvent *event = &queue->events[i];
        event->error = error;
        event->result = result;
        if (result > 0) {
            event->total_result += result;
        }
        return event;
    }

    return NULL;
}


const char* rawstor_io_queue_engine_name(void) {
    return  "aio";
}


RawstorIOQueue* rawstor_io_queue_create(unsigned int depth) {
#ifdef AIO_LISTIO_MAX
    if (depth > AIO_LISTIO_MAX) {
        rawstor_warning(
            "Unable to create Rawstor IO buffer with depth = %d, "
            "falling back to AIO_LISTIO_MAX = %d\n",
            depth, AIO_LISTIO_MAX);
        depth = AIO_LISTIO_MAX;
    }
#endif
    RawstorIOQueue *queue = malloc(sizeof(RawstorIOQueue));
    if (queue == NULL) {
        goto err_queue;
    }

    queue->depth = depth;

    /**
     * TODO: io operations could be much more than depth.
     */
    queue->cbs = calloc(depth, sizeof(struct aiocb));
    if (queue->cbs == NULL) {
        goto err_cbs;
    }

    queue->cbps = calloc(depth, sizeof(struct aiocb*));
    if (queue->cbps == NULL) {
        goto err_cbps;
    }

    queue->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (queue->events_pool == NULL) {
        goto err_events_pool;
    }
    queue->events = rawstor_mempool_data(queue->events_pool);

    for (unsigned int i = 0; i < depth; ++i) {
        queue->events[i].cb = &queue->cbs[i];
        queue->events[i].cbp = &queue->cbps[i];
        queue->cbps[i] = NULL;
    }

    return queue;

err_events_pool:
    free(queue->cbps);
err_cbps:
    free(queue->cbs);
err_cbs:
    free(queue);
err_queue:
    return NULL;
}


void rawstor_io_queue_delete(RawstorIOQueue *queue) {
    rawstor_mempool_delete(queue->events_pool);
    free(queue->cbps);
    free(queue->cbs);
    free(queue);
}


int rawstor_io_queue_setup_fd(int RAWSTOR_UNUSED fd) {
    return 0;
}


int rawstor_io_queue_read(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        goto err_read;
    }

    *event->cbp = event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_pread(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        goto err_read;
    }

    *event->cbp = event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_readv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_readv,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_read;
    }

    *event->cbp = event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_preadv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_preadv,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_read;
    }

    *event->cbp = event->cb;

    return 0;

err_read:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_write(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        goto err_write;
    }

    *event->cbp = event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_pwrite(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        goto err_write;
    }

    *event->cbp = event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_writev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_writev,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
        .data = queue,
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
        goto err_write;
    }

    *event->cbp = event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


int rawstor_io_queue_pwritev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    /**
     * TODO: Do we really need this check?
     */
    if (niov == 0) {
        return 0;
    }

    if (rawstor_mempool_available(queue->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(queue->events_pool);

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
        .callback = io_event_pwritev,
        .size = size,
        .result = 0,
        .total_result = 0,
        .error = EINPROGRESS,
        .data = queue,
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

    if (aio_write(event->cb)) {
        goto err_write;
    }

    *event->cbp = event->cb;

    return 0;

err_write:
    rawstor_mempool_free(queue->events_pool, event);
    return -errno;
}


RawstorIOEvent* rawstor_io_queue_wait_event_timeout(
    RawstorIOQueue *queue, unsigned int timeout)
{
    RawstorIOEvent *event = io_process_event(queue);
    if (event != NULL) {
        return event;
    }

    if (rawstor_mempool_allocated(queue->events_pool) == 0) {
        return NULL;
    }

    struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000ul * timeout,
    };

    if (
        aio_suspend(
            (const struct aiocb* const*)queue->cbps, queue->depth, &ts))
    {
        return NULL;
    }

    return io_process_event(queue);
}


void rawstor_io_queue_release_event(RawstorIOQueue *queue, RawstorIOEvent *event) {
    *event->cbp = NULL;
    rawstor_mempool_free(queue->events_pool, event);
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
