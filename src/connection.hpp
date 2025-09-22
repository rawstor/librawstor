#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include <rawstorstd/mempool.hpp>
#include <rawstorstd/socket_address.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {


struct ConnectionOp;

class Object;

class Socket;


class Connection {
    private:
        unsigned int _depth;

        MemPool<ConnectionOp> _ops;
        std::vector<std::shared_ptr<Socket>> _sockets;
        size_t _socket_index;

        std::shared_ptr<Socket> _get_next_socket();

        ConnectionOp* _acquire_op();
        void _release_op(ConnectionOp* op) noexcept;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        Connection(unsigned int depth);
        Connection(const Connection &) = delete;
        ~Connection();

        Connection& operator=(const Connection&) = delete;

        void create(
            const SocketAddress &ost,
            const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(
            const SocketAddress &ost,
            const RawstorUUID &id);

        void spec(
            const SocketAddress &ost,
            const RawstorUUID &id, RawstorObjectSpec *sp);

        void open(
            const SocketAddress &ost,
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

#endif // RAWSTOR_CONNECTION_HPP
