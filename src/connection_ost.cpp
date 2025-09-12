#include "connection_ost.hpp"

#include "opts.h"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor/object.h>

#include <stdexcept>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256


#define op_trace(cid, event) \
    rawstor_debug( \
        "[%u] %s(): %zi of %zu\n", \
        cid, __FUNCTION__, \
        rawstor_io_event_result(event), \
        rawstor_io_event_size(event))


namespace rawstor {


int Connection::_set_object_cb(
    RawstorObject *,
    size_t size, size_t res, int error, void *data) noexcept
{
    int *completion = (int*)data;

    if (error) {
        return error;
    }

    if (size != res) {
        errno = EIO;
        return -errno;
    }

    --*completion;

    return 0;
}


Connection::Connection(unsigned int depth):
    _depth(depth),
    _socket_index(0)
{}


Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error &e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}


Socket& Connection::_get_next_socket() {
    if (_sockets.empty()) {
        throw std::runtime_error("Empty sockets list");
    }

    Socket &s = _sockets[_socket_index++];
    if (_socket_index >= _sockets.size()) {
        _socket_index = 0;
    }

    return s;
}


void Connection::open(
    const RawstorSocketAddress &ost,
    rawstor::Object *object,
    size_t sockets)
{
    RawstorIOQueue *queue = rawstor_io_queue_create(_depth);
    if (queue == NULL) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    try {
        int completion = sockets;
        _sockets.reserve(sockets);
        for (size_t i = 0; i < sockets; ++i) {
            _sockets.emplace_back(ost, _depth);
            _sockets.back().set_object(
                queue, object,
                _set_object_cb, &completion);
        }

        while (completion > 0) {
            RawstorIOEvent *event = rawstor_io_queue_wait_event_timeout(
                queue, rawstor_opts_wait_timeout());
            if (event == NULL) {
                if (errno) {
                    RAWSTOR_THROW_ERRNO(errno);
                }
                break;
            }

            if (rawstor_io_event_dispatch(event)) {
                RAWSTOR_THROW_ERRNO(errno);
            }

            rawstor_io_queue_release_event(queue, event);
        }

        if (completion > 0) {
            throw std::runtime_error("Falied to set object id");
        }

        rawstor_io_queue_delete(queue);
        queue = NULL;
    } catch (...) {
        _sockets.clear();
        if (queue != NULL) {
            rawstor_io_queue_delete(queue);
        }
        throw;
    }
}


void Connection::close() {
    _sockets.clear();
}


void Connection::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    _get_next_socket().pread(buf, size, offset, cb, data);
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    _get_next_socket().preadv(iov, niov, size, offset, cb, data);
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    _get_next_socket().pwrite(buf, size, offset, cb, data);
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    _get_next_socket().pwritev(iov, niov, size, offset, cb, data);
}


} // rawstor
