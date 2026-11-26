#ifndef RAWSTOR_MDS_RECONCILER_HPP
#define RAWSTOR_MDS_RECONCILER_HPP

#include "store.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/pipe.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace rawstor {
namespace mdsserver {

/*
 * Lists the OSTs whose member digest disagrees with the map (docs/mds.md,
 * "Member digest"), one at a time on a thread of its own, and logs what
 * differs: the members an OST holds that the map does not place on it, and
 * the ones the map places there that it does not hold. The map is left as it
 * is. request() and stop() may be called from any thread, request() under the
 * store's lock too.
 */
class Reconciler final {
private:
    ObjectStore& _store;
    rawstd::Pipe _wake;
    std::unique_ptr<rawio::Queue> _queue;
    std::atomic<bool> _stop_requested{false};
    std::mutex _mutex;
    std::vector<TopologyOST> _requests;
    rawstd::Semaphore _pending{0};
    // The OST being listed, cut short by a stop.
    std::optional<rawstd::Task<void>> _work;

    rawstd::Task<void> _reconcile(TopologyOST ost);
    rawstd::Task<void> _wake_reader();
    rawstd::Task<void> _control();

public:
    explicit Reconciler(ObjectStore& store);
    Reconciler(const Reconciler&) = delete;
    Reconciler& operator=(const Reconciler&) = delete;
    ~Reconciler();

    void loop();
    void request(const TopologyOST& ost);
    void stop() noexcept;
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_RECONCILER_HPP
