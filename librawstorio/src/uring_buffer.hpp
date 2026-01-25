#ifndef RAWSTORIO_URING_BUFFER_HPP
#define RAWSTORIO_URING_BUFFER_HPP

#include <rawstorio/task.hpp>

#include <liburing.h>

#include <list>
#include <memory>

namespace rawstor {
namespace io {
namespace uring {

class BufferRingEntry final {
private:
    io_uring_buf_ring* _buf_ring;

    void* _data;
    size_t _size;
    size_t _result;
    unsigned int _index;
    int _mask;

public:
    BufferRingEntry(
        io_uring_buf_ring* buf_ring, void* data, size_t size,
        unsigned int index, int mask
    );
    BufferRingEntry(const BufferRingEntry&) = delete;
    BufferRingEntry(BufferRingEntry&&) = delete;
    ~BufferRingEntry();

    BufferRingEntry& operator=(const BufferRingEntry&) = delete;
    BufferRingEntry& operator=(BufferRingEntry&&) = delete;

    inline void* data() noexcept { return _data; }
    inline size_t result() noexcept { return _result; }
    inline void set_result(size_t result) noexcept { _result = result; };
};

class BufferRing final : public rawstor::io::Task {
private:
    static __u16 _id_counter;

    const size_t _entry_size;
    const unsigned int _entry_shift;

    const __u16 _id;
    io_uring_buf_ring* _buf_ring;
    size_t _buf_ring_size;
    int _mask;
    char* _entries_base;

    size_t _pending_offset;
    size_t _pending_size;
    std::unique_ptr<BufferRingEntry> _pending_entry;
    std::list<std::unique_ptr<BufferRingEntry>> _pending_entries;

    std::unique_ptr<rawstor::io::TaskVectorExternal> _t;

    void* _get_entry(unsigned int index);

public:
    BufferRing(
        io_uring& ring, size_t entry_size, unsigned int entries,
        std::unique_ptr<rawstor::io::TaskVectorExternal> t
    );
    BufferRing(const BufferRing&) = delete;
    BufferRing(BufferRing&&) = delete;

    ~BufferRing();

    BufferRing& operator=(const BufferRing&) = delete;
    BufferRing& operator=(BufferRing&&) = delete;
    void operator()(size_t result, int error) override;

    void select_entry(unsigned int index);

    unsigned int id() const noexcept;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_BUFFER_HPP
