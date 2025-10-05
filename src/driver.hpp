#ifndef RAWSTOR_DRIVER_HPP
#define RAWSTOR_DRIVER_HPP

#include "object.hpp"

#include <rawstorio/queue.hpp>

#include <rawstor/object.h>

#include <memory>
#include <sstream>


namespace rawstor {


class Driver {
    private:
        unsigned int _depth;
        SocketAddress _ost;
        int _fd;

    protected:
        inline void set_fd(int fd) noexcept {
            _fd = fd;
        }

    public:
        static std::unique_ptr<Driver> create(
            const SocketAddress &ost, unsigned int depth);

        Driver(const SocketAddress &ost, unsigned int depth);
        Driver(const Driver &) = delete;
        Driver(Driver &&other) noexcept;
        virtual ~Driver();

        Driver& operator=(const Driver&) = delete;

        std::string str() const;

        inline const SocketAddress& ost() const noexcept {
            return _ost;
        }

        inline unsigned int depth() const noexcept {
            return _depth;
        }

        inline int fd() const noexcept {
            return _fd;
        }

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
