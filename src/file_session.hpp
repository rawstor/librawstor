#ifndef RAWSTOR_FILE_SESSION_HPP
#define RAWSTOR_FILE_SESSION_HPP

#include "session.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/uuid.h>

#include <string>

namespace rawstor {
namespace file {


class SessionOp;


class Session final: public rawstor::Session {
    private:
        RawstorObject *_object;

        int _connect(const RawstorUUID &id);
    public:
        Session(const URI &uri, unsigned int depth);

        inline RawstorObject* object() const noexcept {
            return _object;
        }

        void create(
            rawstor::io::Queue &queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            std::unique_ptr<rawstor::Task> t);

        void remove(
            rawstor::io::Queue &queue,
            const RawstorUUID &id,
            std::unique_ptr<rawstor::Task> t);

        void spec(
            rawstor::io::Queue &queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            std::unique_ptr<rawstor::Task> t);

        void set_object(
            rawstor::io::Queue &queue,
            RawstorObject *object,
            std::unique_ptr<rawstor::Task> t);

        void pread(
            void *buf, off_t offset,
            std::unique_ptr<rawstor::Task> t);

        void preadv(
            iovec *iov, unsigned int niov, off_t offset,
            std::unique_ptr<rawstor::Task> t);

        void pwrite(
            void *buf, off_t offset,
            std::unique_ptr<rawstor::Task> t);

        void pwritev(
            iovec *iov, unsigned int niov, off_t offset,
            std::unique_ptr<rawstor::Task> t);
};


}} // rawstor::file


#endif // RAWSTOR_FILE_SESSION_HPP
