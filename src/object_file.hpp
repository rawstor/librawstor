#ifndef RAWSTOR_OBJECT_FILE_HPP
#define RAWSTOR_OBJECT_FILE_HPP

#include "connection_ost.hpp"

#include <rawstorstd/mempool.h>

#include <rawstor.h>

namespace rawstor {


class Object {
    private:
        RawstorUUID _id;
        int _fd;
        RawstorMemPool *_ops_pool;

        static int _process(RawstorIOEvent *event, void *data) noexcept;

    public:
        static void create(const RawstorObjectSpec &spec, RawstorUUID *id);
        static void create(
            const RawstorSocketAddress &ost,
            const RawstorObjectSpec &spec,
            RawstorUUID *id);

        static void remove(const RawstorUUID &id);
        static void remove(
            const RawstorSocketAddress &ost,
            const RawstorUUID &id);

        static void spec(const RawstorUUID &id, RawstorObjectSpec *sp);
        static void spec(
            const RawstorSocketAddress &ost,
            const RawstorUUID &id,
            RawstorObjectSpec *spec);

        Object(const RawstorUUID &id);
        Object(const Object&) = delete;

        ~Object();

        Object& operator=(const Object&) = delete;

        void open();
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


#endif // RAWSTOR_OBJECT_FILE_HPP
