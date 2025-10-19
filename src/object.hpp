#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include "connection.hpp"

#include <rawstorstd/uri.hpp>

#include <rawstor.h>

#include <memory>
#include <vector>


struct RawstorObject final {
    private:
        RawstorUUID _id;
        std::vector<std::unique_ptr<rawstor::Connection>> _cns;

    public:
        static void create(
            const std::vector<rawstor::URI> &uris,
            const RawstorObjectSpec &sp,
            RawstorUUID *id);
        static void remove(const std::vector<rawstor::URI> &uris);
        static void spec(
            const std::vector<rawstor::URI> &uris, RawstorObjectSpec *sp);

        explicit RawstorObject(const std::vector<rawstor::URI> &uris);
        RawstorObject(const RawstorObject &) = delete;
        RawstorObject(RawstorObject &&) = delete;
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
