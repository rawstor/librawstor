#ifndef RAWSTOR_OSTBACKEND_SESSION_HPP
#define RAWSTOR_OSTBACKEND_SESSION_HPP

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>
#include <rawstor/rawio.h>

namespace rawstor {
namespace ostbackend {

class Server;

class Session final {
private:
    RawIOQueue* _queue;
    Server& _server;
    int _fd;
    RawIOEvent* _recv_event;
    ssize_t (Session::*_next)(const iovec*, unsigned int, size_t);
    RawstorOSTFrameHead _request_head;
    union {
        RawstorOSTFrameBasicBody basic;
        RawstorOSTFrameIOBody io;
    } _request_body;
    RawstorObject* _object;

    static ssize_t _recv(
        const iovec* iov, unsigned int niov, size_t result, int error,
        void* data
    ) noexcept;
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_data(const iovec* iov, unsigned int niov, size_t result);
    void _set_object(const RawstorOSTFrameBasicBody& request);
    void
    _read(const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body);
    void _write(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
        const iovec* iov, unsigned int niov, size_t size
    );
    void _discard(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
    );

public:
    Session(RawIOQueue* queue, Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session() noexcept;

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SESSION_HPP
