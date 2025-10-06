#ifndef RAWSTOR_FILE_DRIVER_HPP
#define RAWSTOR_FILE_DRIVER_HPP

#include "driver.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/uuid.h>

#include <string>

namespace rawstor {
namespace file {


class DriverOp;


class Driver final: public rawstor::Driver {
    private:
        RawstorObject *_object;

        int _connect(const RawstorUUID &id);
    public:
        Driver(const URI &uri, unsigned int depth);

        inline RawstorObject* object() const noexcept {
            return _object;
        }

        void create(
            rawstor::io::Queue &queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data);

        void remove(
            rawstor::io::Queue &queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data);

        void spec(
            rawstor::io::Queue &queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data);

        void set_object(
            rawstor::io::Queue &queue,
            RawstorObject *object,
            RawstorCallback *cb, void *data);

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


}} // rawstor::file


#endif // RAWSTOR_FILE_DRIVER_HPP
