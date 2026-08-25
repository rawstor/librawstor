#ifndef RAWSTOR_TESTS_RAWIO_SYNC_HPP
#define RAWSTOR_TESTS_RAWIO_SYNC_HPP

#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>

#include <sys/types.h>

namespace rawstor {
namespace tests {

// Drives one of the now-asynchronous rawstor_target_*()/
// rawstor_location_*() calls synchronously to completion against
// `queue`, returning the same ssize_t (0/positive on success, negative
// errno on failure) every one of these tests used to get directly from
// the old synchronous C API. `submit` must call the async function
// itself, forwarding `cb`/`data` as its own trailing two arguments, and
// return that call's own synchronous result.
//
// Usage:
//   ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
//       return rawstor_target_create(queue, target.c_str(), &spec, cb, data);
//   });
template <typename F>
ssize_t sync_run(RawIOQueue* queue, F&& submit) {
    struct Op {
        ssize_t result;
        bool done;
    };
    Op op{0, false};

    int (*cb)(ssize_t, void*) = [](ssize_t result, void* data) -> int {
        Op* op = static_cast<Op*>(data);
        op->result = result;
        op->done = true;
        return 0;
    };

    int res = submit(cb, static_cast<void*>(&op));
    if (res < 0) {
        return res;
    }

    while (!op.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-wres);
        }
    }

    return op.result;
}

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_RAWIO_SYNC_HPP
