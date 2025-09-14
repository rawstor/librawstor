#ifndef RAWSTOR_CONNECTION_OST_HPP
#define RAWSTOR_CONNECTION_OST_HPP

#include "socket.hpp"

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <cstddef>
#include <vector>

namespace rawstor {


class Object;


class Connection {
    private:
        unsigned int _depth;

        std::vector<Socket> _sockets;
        size_t _socket_index;

        Socket& _get_next_socket();
    public:
        Connection(unsigned int depth);
        Connection(const Connection &) = delete;
        ~Connection();

        Connection& operator=(const Connection&) = delete;

        void create(
            const RawstorSocketAddress &ost,
            const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(
            const RawstorSocketAddress &ost,
            const RawstorUUID &id);

        void spec(
            const RawstorSocketAddress &ost,
            const RawstorUUID &id, RawstorObjectSpec *sp);

        void open(
            const RawstorSocketAddress &ost,
            rawstor::Object *object,
            size_t sockets);

        void close();

        void pread(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void preadv(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void pwrite(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void pwritev(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);
};


} // rawstor

#endif // RAWSTOR_CONNECTION_OST_HPP
