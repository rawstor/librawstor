#ifndef RAWSTOR_DRIVER_HPP
#define RAWSTOR_DRIVER_HPP

#include "object.hpp"

#include <rawstorio/queue.hpp>

#include <rawstor/object.h>

#include <sstream>


namespace rawstor {


class Driver {
    protected:
        SocketAddress _ost;
        int _fd;

    public:
        Driver(const SocketAddress &ost);
        Driver(const Driver &) = delete;
        Driver(Driver &&other) noexcept;
        virtual ~Driver();

        Driver& operator=(const Driver&) = delete;

        std::string str() const;

        const SocketAddress& ost() const noexcept;

        virtual void create(
            rawstor::io::Queue &queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data) = 0;

        virtual void remove(
            rawstor::io::Queue &queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data) = 0;

        virtual void spec(
            rawstor::io::Queue &queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data) = 0;

        virtual void set_object(
            rawstor::io::Queue &queue,
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

#endif // RAWSTOR_DRIVER_HPP
