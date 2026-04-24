#ifndef RAWSTOR_OSTBACKEND_SESSION_HPP
#define RAWSTOR_OSTBACKEND_SESSION_HPP

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>
#include <rawstor/rawstor.h>

namespace rawstor {
namespace ostbackend {

class Server;

class Session final {
private:
    Server& _server;
    int _fd;
    RawstorIOEvent* _recv_event;
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
    );
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_data(const iovec* iov, unsigned int niov, size_t result);
    void _set_object(const RawstorOSTFrameBasicBody& request);
    void _read(const RawstorOSTFrameIOBody& request);
    void _write(
        const RawstorOSTFrameIOBody& request, const iovec* iov,
        unsigned int niov, size_t size
    );
    void _discard(const RawstorOSTFrameIOBody& request);

public:
    Session(Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session();

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SESSION_HPP
