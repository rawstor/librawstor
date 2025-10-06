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


class Connection {
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

        std::unique_ptr<ConnectionOp> pread(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        std::unique_ptr<ConnectionOp> preadv(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        std::unique_ptr<ConnectionOp> pwrite(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        std::unique_ptr<ConnectionOp> pwritev(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void submit(ConnectionOp *op);
};


class ConnectionOp {
    private:
        rawstor::Connection &_cn;
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<rawstor::Driver> _s;
        unsigned int _attempts;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        ConnectionOp(rawstor::Connection &cn, RawstorCallback *cb, void *data);
        ConnectionOp(const ConnectionOp &) = delete;
        ConnectionOp(ConnectionOp &&) = delete;
        ConnectionOp& operator=(const ConnectionOp &) = delete;
        ConnectionOp& operator=(ConnectionOp &&) = delete;
        virtual ~ConnectionOp() {}

        virtual void operator()(const std::shared_ptr<rawstor::Driver> &s) = 0;

        virtual std::string str() const = 0;

        inline int callback(
            RawstorObject *object, size_t size, size_t res, int error)
        {
            return _cb(object, size, res, error, _data);
        }
};


} // rawstor

#endif // RAWSTOR_CONNECTION_HPP
