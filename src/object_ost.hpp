#ifndef RAWSTOR_OBJECT_OST_HPP
#define RAWSTOR_OBJECT_OST_HPP

#include "connection_ost.hpp"

#include <rawstorstd/mempool.h>

#include <rawstor.h>

namespace rawstor {


class Object {
    private:
        RawstorUUID _id;
        RawstorMemPool *_ops_pool;
        Connection *_cn;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        Object(const RawstorUUID *object_id);
        Object(const Object&) = delete;

        ~Object();

        Object& operator=(const Object&) = delete;

        void open(const RawstorSocketAddress &ost);

        void close();

        const RawstorUUID& id() const noexcept;

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


#endif // RAWSTOR_OBJECT_OST_HPP
