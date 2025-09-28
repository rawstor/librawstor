#ifndef RAWSTOR_SOCKET_HPP
#define RAWSTOR_SOCKET_HPP

#include "object.hpp"

#include <rawstorio/queue.h>

#include <rawstor/object.h>

#include <sstream>


namespace rawstor {


class Socket {
    protected:
        SocketAddress _ost;
        int _fd;

    public:
        Socket(const SocketAddress &ost);
        Socket(const Socket &) = delete;
        Socket(Socket &&other) noexcept;
        virtual ~Socket();

        Socket& operator=(const Socket&) = delete;

        std::string str() const;

        const SocketAddress& ost() const noexcept;

        virtual void create(
            RawstorIOQueue *queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data) = 0;

        virtual void remove(
            RawstorIOQueue *queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data) = 0;

        virtual void spec(
            RawstorIOQueue *queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data) = 0;

        virtual void set_object(
            RawstorIOQueue *queue,
            rawstor::Object *object,
            RawstorCallback *cb, void *data) = 0;

        virtual void pread(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data) = 0;

        virtual void preadv(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data) = 0;

        virtual void pwrite(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data) = 0;

        virtual void pwritev(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data) = 0;
};


} //rawstor

#endif // RAWSTOR_SOCKET_HPP
