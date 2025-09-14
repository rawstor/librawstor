#ifndef RAWSTOR_SOCKET_FILE_HPP
#define RAWSTOR_SOCKET_FILE_HPP

#include <rawstorstd/mempool.h>

#include <rawstorio/queue.h>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <string>

namespace rawstor {


struct SocketOp;

class Object;


class Socket {
    private:
        int _fd;
        Object *_object;
        RawstorMemPool *_ops_pool;
        std::string _ost_path;

        SocketOp* _pop_op();
        void _push_op(SocketOp *op);

        static int _io_cb(RawstorIOEvent *event, void *data) noexcept;

    public:
        static const char* engine_name() noexcept;

        Socket(const RawstorSocketAddress &ost, unsigned int depth);
        Socket(const Socket &) = delete;
        Socket(Socket &&other) noexcept;
        ~Socket();

        Socket& operator=(const Socket&) = delete;

        void create(
            RawstorIOQueue *queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data);

        void remove(
            RawstorIOQueue *queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data);

        void spec(
            RawstorIOQueue *queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data);

        void set_object(
            RawstorIOQueue *queue,
            rawstor::Object *object,
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


} // rawstor


#endif // RAWSTOR_OBJECT_SOCKET_HPP
