#ifndef RAWSTOR_OSTSERVER_CLIENT_HPP
#define RAWSTOR_OSTSERVER_CLIENT_HPP

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace rawstor {
namespace ostserver {

class Server;

class Client final : public std::enable_shared_from_this<Client> {
private:
    struct Private {
        explicit Private() = default;
    };

    RawIOQueue* _queue;
    Server& _server;
    int _fd;
    RawIOEvent* _recv_event;
    RawstorObject* _object;

    // Drives this Client's whole request-dispatch lifetime: registers the
    // multishot recv, then loops co_awaiting one length-prefixed frame at
    // a time (head, then a command-dependent body, then -- for WRITE --
    // the payload), dispatching each to the matching _list()/_read()/...
    // fire-and-forget launcher as soon as it's fully read, exactly like
    // the old synchronous _recv_head()/_recv_body()/_recv_data() state
    // machine did, but as ordinary sequential coroutine code instead of a
    // C-callback-driven one. `queue`/`fd` are taken explicitly (Client::
    // create() already has them on hand) rather than through a `weak.
    // lock()` at the top, so registration doesn't need a live Client at
    // all -- only actually reaching into one, via `weak`, once dispatch
    // begins. See the .cpp for why this can't just be a coroutine-local
    // recv stream the way ost/src/ost_backend.cpp's rawio::RecvStream is.
    static rawstd::DetachedTask
    _recv_pump(std::weak_ptr<Client> weak, RawIOQueue* queue, int fd);

    // Every _*() below is `static` (no implicit `this`) and takes a
    // `weak_ptr<Client>` explicitly: each is a coroutine that may co_await
    // across a suspension the Client itself might not survive (e.g. the
    // peer disconnects and something else tears the client down while an
    // object close/open/I-O op this coroutine started is still in flight),
    // so nothing here may touch a Client through anything but a freshly
    // re-`lock()`-ed shared_ptr, immediately before use, never a captured
    // one held across a `co_await`. `static` makes that discipline the
    // only way to reach a Client at all, rather than relying on nobody
    // reaching for an implicit `this` by mistake.
    //
    // Each returns rawstd::DetachedTask (a fire-and-forget launch, not
    // something a caller holds/awaits) -- every call site must call
    // rawstd::DetachedTask::rethrow_if_pending() immediately after, per its
    // own doc comment (librawstd/include/rawstd/coro.hpp): _recv_pump()'s
    // dispatch switch is the only caller for most of these, with _write()
    // additionally launching _dispatch_write() itself once it validates the
    // incoming WRITE's hash.
    //
    // Closes `client->_object` (if any) before the rest of a `_*()` runs --
    // shared by _list()/_allocate()/_set_object(). Returns the still-live
    // Client to continue with, or nullptr if the caller should co_return
    // immediately (either the Client was already gone, or the close failed
    // and this already tore the client down via Server::del_client(),
    // matching how a thrown exception elsewhere in the recv dispatch loop
    // is handled by _recv_pump()'s own catch blocks -- there's no such
    // enclosing catch by the time an async close's completion resumes
    // this, so it's handled directly instead).
    static rawstd::Task<std::shared_ptr<Client>>
    _close_current_object(std::weak_ptr<Client> weak);

    static rawstd::DetachedTask _list(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameBasicPayload payload
    );
    static rawstd::DetachedTask _allocate(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameAllocatePayload payload
    );
    static rawstd::DetachedTask _release(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameBasicPayload payload
    );
    static rawstd::DetachedTask _spec(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameBasicPayload payload
    );
    static rawstd::DetachedTask _meta(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameBasicPayload payload
    );
    static rawstd::DetachedTask
    _info(std::weak_ptr<Client> weak, RawstorOSTFrameHead head);
    static rawstd::DetachedTask _set_object(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameBasicPayload payload
    );
    static rawstd::DetachedTask _read(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameIOPayload payload
    );
    static rawstd::DetachedTask _write(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameIOPayload payload,
        std::shared_ptr<std::vector<unsigned char>> data
    );
    // Issues a validated WRITE to storage -- rawstor_object_pwrite()'s
    // underlying blk::Backend applies write-throttling itself (see
    // blk_backend.hpp's _throttle_acquire()), so this just dispatches.
    static rawstd::DetachedTask _dispatch_write(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head, uint64_t offset,
        bool sync, std::shared_ptr<std::vector<unsigned char>> data
    );
    static rawstd::DetachedTask _discard(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameIOPayload payload
    );
    static rawstd::DetachedTask _write_zeroes(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameIOPayload payload
    );
    static rawstd::DetachedTask
    _flush(std::weak_ptr<Client> weak, RawstorOSTFrameHead head);
    static rawstd::DetachedTask _set_state(
        std::weak_ptr<Client> weak, RawstorOSTFrameHead head,
        RawstorOSTFrameSyncStatePayload payload
    );
    std::vector<rawstd::URI> _targets(const RawstdUUID& uuid);

    // Sends a response frame and awaits its actual completion (not just
    // submission) -- unlike every other rawio_*() bridge in the .cpp,
    // there's no separate fire-and-forget IOCallback anymore: a failure
    // here (submission *or* completion) throws uniformly, for the caller
    // (always one of the _*()s above) to tear the client down via
    // Server::del_client(), the same way it already handles any other
    // failure.
    rawstd::Task<void> _send_response(
        const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash
    );
    rawstd::Task<void> _send_response(
        const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash, const std::vector<unsigned char>& data
    );

public:
    static rawstd::Task<std::shared_ptr<Client>>
    create(RawIOQueue* queue, Server& server, int fd);

    Client(Private, RawIOQueue* queue, Server& server, int fd);
    Client(const Client&) = delete;
    Client(Client&&) = delete;
    ~Client() noexcept;

    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;

    // Asynchronously closes this client's open object (if any), then its
    // connection fd, cancelling the still-armed recv registration first.
    // Never throws -- every failure along the way is logged and otherwise
    // ignored, same as ~Client()'s own (synchronous) cleanup. Not required
    // before destruction: ~Client() falls back to the same cleanup,
    // synchronously, for whichever of _object/_fd/_recv_event this didn't
    // already get to (each is cleared here as it's closed, so the two
    // never redo each other's work).
    rawstd::Task<void> close();
};

} // namespace ostserver
} // namespace rawstor

#endif // RAWSTOR_OSTSERVER_CLIENT_HPP
