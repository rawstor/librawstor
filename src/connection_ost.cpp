#include "connection_ost.hpp"

#include "object_ost.hpp"
#include "opts.h"
#include "ost_protocol.h"

#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <arpa/inet.h>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
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


Connection::Connection(unsigned int depth):
    _object(nullptr),
    _depth(depth),
    _socket_index(0)
{}


Connection::~Connection() {
    if (_object != nullptr) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Connection::close(): %s\n", e.what());
        }
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


unsigned int Connection::depth() const noexcept {
    return _depth;
}


void Connection::create(
    const RawstorSocketAddress &ost,
    const RawstorObjectSpec &sp,
    RawstorUUID *id)
{
    Socket(*this).create(ost, sp, id);
}


void Connection::remove(rawstor::Object *object, const RawstorSocketAddress &ost) {
    Socket s(*this);
    s.remove(object, ost);
}


void Connection::spec(
    rawstor::Object *object,
    const RawstorSocketAddress &ost,
    RawstorObjectSpec *sp)
{
    Socket(*this).spec(object, ost, sp);
}


void Connection::open(
    rawstor::Object *object,
    const RawstorSocketAddress &ost,
    size_t count)
{
    if (_object != nullptr) {
        throw std::runtime_error("Connection already opened");
    }

    _sockets.reserve(count);
    try {
        for (size_t i = 0; i < count; ++i) {
            _sockets.emplace_back(*this);
            _sockets.back().open(object, ost);
        }
    } catch (...) {
        _sockets.clear();
        throw;
    }

    _object = object;
}


void Connection::close() {
    if (_object == nullptr) {
        throw std::runtime_error("Connection not opened");
    }

    _sockets.clear();

    _object = nullptr;
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
