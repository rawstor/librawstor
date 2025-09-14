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


namespace {


class Queue {
    private:
        int _operations;
        RawstorIOQueue *_impl;

    public:
        static int callback(
            RawstorObject *,
            size_t size, size_t res, int error, void *data) noexcept;

        Queue(int operations, unsigned int depth);
        Queue(const Queue &) = delete;
        ~Queue();

        Queue& operator=(const Queue &) = delete;

        explicit operator RawstorIOQueue*() noexcept;

        void wait();
};


Queue::Queue(int operations, unsigned int depth):
    _operations(operations),
    _impl(nullptr)
{
    _impl = rawstor_io_queue_create(depth);
    if (_impl == nullptr) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}

Queue::~Queue() {
    rawstor_io_queue_delete(_impl);
}


int Queue::callback(
    RawstorObject *,
    size_t size, size_t res, int error, void *data) noexcept
{
    Queue *queue = static_cast<Queue*>(data);

    --queue->_operations;

    if (error) {
        return error;
    }

    if (size != res) {
        errno = EIO;
        return -errno;
    }

    return 0;
}


Queue::operator RawstorIOQueue*() noexcept {
    return _impl;
}


void Queue::wait() {
    while (_operations > 0) {
        RawstorIOEvent *event = rawstor_io_queue_wait_event_timeout(
            _impl, rawstor_opts_wait_timeout());
        if (event == NULL) {
            if (errno) {
                RAWSTOR_THROW_ERRNO(errno);
            }
            break;
        }

        if (rawstor_io_event_dispatch(event)) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        rawstor_io_queue_release_event(_impl, event);
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


} // unnamed namespace


namespace rawstor {


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


void Connection::create(
    const RawstorSocketAddress &ost,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.create(static_cast<RawstorIOQueue*>(q), sp, id, q.callback, &q);

    q.wait();
}


void Connection::remove(
    const RawstorSocketAddress &ost,
    const RawstorUUID &id)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.remove(static_cast<RawstorIOQueue*>(q), id, q.callback, &q);

    q.wait();
}


void Connection::spec(
    const RawstorSocketAddress &ost,
    const RawstorUUID &id, RawstorObjectSpec *sp)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.spec(static_cast<RawstorIOQueue*>(q), id, sp, q.callback, &q);

    q.wait();
}


void Connection::open(
    const RawstorSocketAddress &ost,
    rawstor::Object *object,
    size_t sockets)
{
    Queue q(sockets, _depth);

    try {
        _sockets.reserve(sockets);
        for (size_t i = 0; i < sockets; ++i) {
            _sockets.emplace_back(ost, _depth);
            _sockets.back().set_object(
                static_cast<RawstorIOQueue*>(q), object, q.callback, &q);
        }

        q.wait();
    } catch (...) {
        _sockets.clear();
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
