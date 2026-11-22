#ifndef RAWIO_URING_BUFFER_HPP
#define RAWIO_URING_BUFFER_HPP

#include <rawio/stream.hpp>

#include <rawstd/ringbuf.hpp>

#include <liburing.h>

#include <coroutine>
#include <list>
#include <memory>

namespace rawio {
namespace uring {

class Queue;
class BufferRing;

class BufferRingEntry final {
private:
    BufferRing* _owner;
    io_uring_buf_ring* _buf_ring;

    void* _data;
    size_t _size;
    size_t _result;
    unsigned int _index;
    int _mask;

public:
    BufferRingEntry(
        BufferRing* owner, io_uring_buf_ring* buf_ring, void* data, size_t size,
        size_t result, unsigned int index, int mask
    );
    BufferRingEntry(const BufferRingEntry&) = delete;
    BufferRingEntry(BufferRingEntry&&) = delete;
    ~BufferRingEntry();

    BufferRingEntry& operator=(const BufferRingEntry&) = delete;
    BufferRingEntry& operator=(BufferRingEntry&&) = delete;

    inline void* data() noexcept { return _data; }
    inline size_t result() noexcept { return _result; }
};

/**
 * Owns the io_uring provided-buffer-ring registration for one
 * recv_multishot() registration, and implements RecvStream::Backend on
 * top of it: `on_arrival()` (called from the completion path once per
 * CQE) accounts newly-arrived data into `_pending_entries`;
 * `try_produce()` (called both directly by RecvStream::Next::await_ready()
 * and internally, for a parked waiter, from on_arrival()) is the one
 * place that turns pending entries into a delivered item -- see the .cpp
 * for the exact want/terminal-error precedence rules.
 */
class BufferRing final : public rawio::RecvStream::Backend,
                         public std::enable_shared_from_this<BufferRing> {
private:
    static __u16 _id_counter;

    Queue& _q;
    io_uring& _ring;

    const size_t _entry_size;
    const unsigned int _entry_shift;
    const unsigned int _entries;

    int _fd;
    unsigned int _flags;

    // Buffers that are in the ring, free for the kernel to fill.
    unsigned int _free;
    // The registration ended because the ring had no free buffer (what the
    // kernel could not take is still in the socket): it is submitted again
    // as soon as a buffer comes back.
    bool _starved;
    bool _cancel_requested;

    const __u16 _id;
    io_uring_buf_ring* _buf_ring;
    size_t _buf_ring_size;
    int _mask;
    char* _entries_base;

    size_t _pending_offset;
    size_t _pending_size;
    rawstd::RingBuf<BufferRingEntry> _pending_entries;

    std::coroutine_handle<> _waiter;
    size_t _waiter_want;
    rawio::RecvStream::Item* _waiter_item;
    int* _waiter_error;

    bool _has_terminal;
    int _terminal_error;
    bool _closed;

    Event* _event;

    void* _get_entry(unsigned int index);

    void _extract(size_t want, rawio::RecvStream::Item& out);

    // Submits the registration again after it ended for lack of buffers.
    bool _resubmit() noexcept;

    // Hands what is pending, or the end of the stream, to a consumer that
    // waits for it.
    void _wake_waiter();

public:
    BufferRing(
        Queue& q, io_uring& ring, size_t entry_size, unsigned int entries
    );
    BufferRing(const BufferRing&) = delete;
    BufferRing(BufferRing&&) = delete;

    ~BufferRing() override;

    BufferRing& operator=(const BufferRing&) = delete;
    BufferRing& operator=(BufferRing&&) = delete;

    unsigned int id() const noexcept;

    inline void set_event(Event* event) noexcept { _event = event; }

    // What the registration is made of, for submitting it again.
    inline void set_source(int fd, unsigned int flags) noexcept {
        _fd = fd;
        _flags = flags;
    }

    // Called when a buffer of a delivered item is given back to the ring.
    void on_release() noexcept;

    // Called once per CQE belonging to this registration: `result` is the
    // raw signed CQE result (negative -errno, or a non-negative byte
    // count), `flags` is the CQE's flags (IORING_CQE_F_BUFFER handling).
    void on_arrival(int result, unsigned int flags);

    bool try_produce(
        size_t want, rawio::RecvStream::Item& out, int& error
    ) noexcept override;
    void set_waiter(
        std::coroutine_handle<> h, size_t want, rawio::RecvStream::Item* out,
        int* error
    ) noexcept override;
    void close() noexcept override;
    void cancel() noexcept override;
    rawio::Event* event() const noexcept override { return _event; }
};

} // namespace uring
} // namespace rawio

#endif // RAWIO_URING_BUFFER_HPP
