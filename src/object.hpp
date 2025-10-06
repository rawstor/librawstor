#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "connection.hpp"

#include <rawstorstd/mempool.hpp>
#include <rawstorstd/uri.hpp>

#include <rawstor.h>

#include <memory>


namespace rawstor {


struct ObjectOp;


} // rawstor


struct RawstorObject final {
    private:
        RawstorUUID _id;
        rawstor::MemPool<rawstor::ObjectOp> _ops;
        rawstor::Connection _cn;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        static void create(
            const rawstor::URI &uri,
            const RawstorObjectSpec &sp,
            RawstorUUID *id);
        static void remove(const rawstor::URI &uri);
        static void spec(const rawstor::URI &uri, RawstorObjectSpec *sp);

        explicit RawstorObject(const rawstor::URI &uri);
        RawstorObject(const RawstorObject &) = delete;
        RawstorObject(RawstorObject &&) = delete;
        ~RawstorObject() {}
        RawstorObject& operator=(const RawstorObject &) = delete;
        RawstorObject& operator=(RawstorObject &&) = delete;

        inline const RawstorUUID& id() const noexcept {
            return _id;
        }

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


#endif // RAWSTOR_OBJECT_HPP
