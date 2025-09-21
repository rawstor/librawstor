#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "connection.hpp"

#include <rawstorstd/mempool.hpp>

#include <rawstor.h>

namespace rawstor {


struct ObjectOp;


class Object {
    private:
        RawstorObject *_c_ptr;
        RawstorUUID _id;
        MemPool<ObjectOp> _ops;
        Connection _cn;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        static void create(const RawstorObjectSpec &sp, RawstorUUID *id);
        static void create(
            const RawstorSocketAddress &ost,
            const RawstorObjectSpec &sp,
            RawstorUUID *id);

        Object(const RawstorUUID &id);
        Object(const Object &) = delete;

        ~Object();

        Object& operator=(const Object&) = delete;

        RawstorObject* c_ptr() noexcept;

        const RawstorUUID& id() const noexcept;

        void remove();
        void remove(const RawstorSocketAddress &ost);

        void spec(RawstorObjectSpec *sp);
        void spec(const RawstorSocketAddress &ost, RawstorObjectSpec *sp);

        void open();
        void open(const RawstorSocketAddress &ost);

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


#endif // RAWSTOR_OBJECT_HPP
