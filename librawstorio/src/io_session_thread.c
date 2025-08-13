#include "io_session_thread.h"

#include "io_event_thread.h"
#include "io_session_seekable_thread.h"
#include "io_session_unseekable_thread.h"
#include "io_thread.h"

#include <rawstorstd/iovec.h>
#include <rawstorstd/list.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/threading.h>

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct RawstorIOSession {
    RawstorIO *io;

    int fd;
    int write;

    void *impl;
    void (*delete)(void *impl);
    int (*push_sqe)(void *impl, RawstorIOEvent *event);
};


static int is_seekable(int fd) {
    if (lseek(fd, 0, SEEK_CUR) == -1) {
        if (errno == ESPIPE) {
            errno = 0;
            return 0;
        }
        return -errno;
    }

    return 1;
}


RawstorIOSession* rawstor_io_session_create(
    RawstorIO *io, int fd, int write)
{
    int seekable = is_seekable(fd);
    if (seekable < 0) {
        goto err_seekable;
    }

    RawstorIOSession *session = malloc(sizeof(RawstorIOSession));
    if (session == NULL) {
        goto err_session;
    }

    if (seekable) {
        *session = (RawstorIOSession) {
            .io = io,
            .fd = fd,
            .write = write,
            // .impl
            .delete = (void(*)(void*))rawstor_io_session_seekable_delete,
            .push_sqe =
                (int(*)(void*, RawstorIOEvent*))
                rawstor_io_session_seekable_push_sqe,
        };
        session->impl = rawstor_io_session_seekable_create(session);
        if (session->impl == NULL) {
            goto err_session_impl;
        }
    } else {
        *session = (RawstorIOSession) {
            .io = io,
            .fd = fd,
            .write = write,
            // .impl
            .delete = (void(*)(void*))rawstor_io_session_unseekable_delete,
            .push_sqe =
                (int(*)(void*, RawstorIOEvent*))
                rawstor_io_session_unseekable_push_sqe,
        };
        session->impl = rawstor_io_session_unseekable_create(session);
        if (session->impl == NULL) {
            goto err_session_impl;
        }
    }

    return session;

err_session_impl:
    free(session);
err_session:
err_seekable:
    return NULL;
}


void rawstor_io_session_delete(RawstorIOSession *session) {
    session->delete(session->impl);
    free(session);
}


RawstorIO* rawstor_io_session_io(RawstorIOSession *session) {
    return session->io;
}


int rawstor_io_session_fd(RawstorIOSession *session) {
    return session->fd;
}


int rawstor_io_session_write(RawstorIOSession *session) {
    return session->write;
}

int rawstor_io_session_push_sqe(
    RawstorIOSession *session, RawstorIOEvent *event)
{
    return session->push_sqe(session->impl, event);
}


int rawstor_io_session_kill(RawstorIOSession *session) {
    return session->fd = -1;
}


int rawstor_io_session_alive(RawstorIOSession *session) {
    return session->fd >= 0;
}


int rawstor_io_session_compare(RawstorIOSession *session, int fd, int write) {
    return session->fd == fd && session->write == write;
}
