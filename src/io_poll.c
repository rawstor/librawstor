#include "io.h"

#include "logging.h"
#include "mempool.h"

#include <poll.h>

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


struct RawstorIOEvent {
    struct pollfd *fd;

    unsigned int ciov;
    struct iovec *iov;
    unsigned int niov;
    off_t offset;
    ssize_t (*process)(RawstorIOEvent *event);

    RawstorIOCallback *callback;

    size_t size;
    ssize_t result;
    int error;

    void *data;
};


struct RawstorIO {
    unsigned int depth;

    RawstorMemPool *events_pool;
    RawstorIOEvent *events;
    struct pollfd *fds;
};


const char* rawstor_io_engine_name = "poll";


static ssize_t io_event_process_readv(RawstorIOEvent *event) {
    ssize_t ret = readv(
        event->fd->fd,
        &event->iov[event->ciov], event->niov - event->ciov);
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_preadv(RawstorIOEvent *event) {
    ssize_t ret = preadv(
        event->fd->fd,
        &event->iov[event->ciov], event->niov - event->ciov, event->offset);
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_writev(RawstorIOEvent *event) {
    ssize_t ret = writev(
        event->fd->fd,
        &event->iov[event->ciov], event->niov - event->ciov);
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static ssize_t io_event_process_pwritev(RawstorIOEvent *event) {
    ssize_t ret = pwritev(
        event->fd->fd,
        &event->iov[event->ciov], event->niov - event->ciov, event->offset);
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


static RawstorIOEvent* io_process_event(RawstorIO *io) {
    for (size_t i = 0; i < io->depth; ++i) {
        struct pollfd *fd = &io->fds[i];
        if (fd->fd < 0) {
            continue;
        }

        RawstorIOEvent *event = &io->events[i];
        if (fd->revents & fd->events) {
            ssize_t res = event->process(event);
            if (res > 0) {
                if ((size_t)res != event->size) {
                    rawstor_debug("partial %zd of %zu\n", res, event->size);
                }
                event->offset += res;
                while (
                    event->ciov < event->niov
                    && (size_t)res >= event->iov[event->ciov].iov_len)
                {
                    res -= event->iov[event->ciov].iov_len;
                    ++event->ciov;
                }
                if (event->ciov == event->niov) {
                    return event;
                }
                event->iov[event->ciov].iov_base += res;
                event->iov[event->ciov].iov_len -= res;
            } else if (res == 0) {
                return event;
            }
        }
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
    io->fds = calloc(depth, sizeof(struct pollfd));
    if (io->fds == NULL) {
        free(io);
        return NULL;
    }

    io->events_pool = rawstor_mempool_create(depth, sizeof(RawstorIOEvent));
    if (io->events_pool == NULL) {
        free(io->fds);
        free(io);
        return NULL;
    }
    io->events = rawstor_mempool_data(io->events_pool);

    for (unsigned int i = 0; i < depth; ++i) {
        io->events[i].fd = &io->fds[i];
        io->fds[i].fd = -1;
    }

    return io;
}


void rawstor_io_delete(RawstorIO *io) {
    rawstor_mempool_delete(io->events_pool);
    free(io->fds);
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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = 1,
        // .offset
        .process = io_event_process_readv,
        .callback = cb,
        .size = size,
        .result = 0,
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = 1,
        .offset = offset,
        .process = io_event_process_preadv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = niov,
        // .offset
        .process = io_event_process_readv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = niov,
        .offset = offset,
        .process = io_event_process_preadv,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLIN,
        .revents = 0,
    };

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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = 1,
        // .offset
        .process = io_event_process_writev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

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
    struct iovec *event_iov = malloc(sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    event_iov[0] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = 1,
        .offset = offset,
        .process = io_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = niov,
        // .offset
        .process = io_event_process_writev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

    return 0;
}


int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_mempool_available(io->events_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    struct iovec *event_iov = calloc(niov, sizeof(struct iovec));
    if (event_iov == NULL) {
        return -errno;
    }
    RawstorIOEvent *event = rawstor_mempool_alloc(io->events_pool);

    for (unsigned int i = 0; i < niov; ++i) {
        event_iov[i] = iov[i];
    }
    *event = (RawstorIOEvent) {
        .fd = event->fd,
        .ciov = 0,
        .iov = event_iov,
        .niov = niov,
        .offset = offset,
        .process = io_event_process_pwritev,
        .callback = cb,
        .size = size,
        // .result
        // .error
        .data = data,
    };

    *event->fd = (struct pollfd) {
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };

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

    while (1) {
        if (poll(io->fds, io->depth, -1) <= 0) {
            return NULL;
        }

        event = io_process_event(io);
        if (event != NULL) {
            return event;
        }
    }
}


RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout) {
    RawstorIOEvent *event = io_process_event(io);
    if (event != NULL) {
        return event;
    }

    if (rawstor_mempool_allocated(io->events_pool) == 0) {
        return NULL;
    }

    while (1) {
        if (poll(io->fds, io->depth, timeout) <= 0) {
            return NULL;
        }

        event = io_process_event(io);
        if (event != NULL) {
            return event;
        }
    }
}


void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event) {
    event->fd->fd = -1;
    free(event->iov);
    rawstor_mempool_free(io->events_pool, event);
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd->fd;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
    return event->callback(event, event->data);
}
