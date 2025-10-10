#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include <rawstorstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <vector>

#include <cstddef>


namespace rawstor {


class ConnectionOp;

class Driver;


class Connection final {
    private:
        RawstorObject *_object;
        unsigned int _depth;

        std::vector<std::shared_ptr<Driver>> _sessions;
        size_t _session_index;

        std::vector<std::shared_ptr<Driver>> _open(
            const URI &uri,
            RawstorObject *object,
            size_t nsessions);

        std::shared_ptr<Driver> _get_next_session();

    public:
        Connection(unsigned int depth);
        Connection(const Connection &) = delete;
        ~Connection();

        Connection& operator=(const Connection&) = delete;

        void invalidate_session(const std::shared_ptr<Driver> &s);

        void create(
            const URI &uri,
            const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(const URI &uri);

        void spec(const URI &uri, RawstorObjectSpec *sp);

        void open(const URI &uri, RawstorObject *object, size_t nsessions);

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

        void retry(ConnectionOp *op);
};


} // rawstor

#endif // RAWSTOR_CONNECTION_HPP
