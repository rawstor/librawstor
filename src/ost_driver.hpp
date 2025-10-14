#ifndef RAWSTOR_OST_DRIVER_HPP
#define RAWSTOR_OST_DRIVER_HPP

#include "driver.hpp"
#include "ost_protocol.h"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <string>
#include <unordered_map>

#include <cstddef>

namespace rawstor {
namespace ost {


class Context;


class Driver final: public rawstor::Driver {
    private:
        uint16_t _cid_counter;

        RawstorObject *_object;

        std::shared_ptr<Context> _context;

        int _connect();

    public:
        Driver(const URI &uri, unsigned int depth);
        ~Driver();

        inline RawstorObject* object() noexcept {
            return _object;
        }

        void read_response_head(rawstor::io::Queue &queue);
        void read_response_body(
            rawstor::io::Queue &queue, uint16_t cid,
            void *buf, size_t size);
        void read_response_body(
            rawstor::io::Queue &queue, uint16_t cid,
            iovec *iov, unsigned int niov, size_t size);

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


}} // rawstor::ost

#endif // RAWSTOR_OST_DRIVER_HPP
