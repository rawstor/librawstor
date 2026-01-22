#ifndef RAWSTORIO_URING_TASK_HPP
#define RAWSTORIO_URING_TASK_HPP

#include <rawstorio/task.hpp>

#include <liburing.h>

#include <memory>

namespace rawstor {
namespace io {
namespace uring {

class BufferRingEntry {
private:
    io_uring_buf_ring* _buf_ring;

    void* _data;
    size_t _size;
    unsigned int _index;
    int _mask;

public:
    BufferRingEntry(
        io_uring_buf_ring* buf_ring, void* data, size_t size,
        unsigned int index, int mask
    );
    ~BufferRingEntry();

    inline void* data() noexcept { return _data; }
};

class TaskBufferRing final : public rawstor::io::Task {
private:
    static __u16 _id_counter;

    const unsigned int _entry_size;
    const unsigned int _entry_shift;

    const __u16 _id;
    io_uring_buf_ring* _buf_ring;
    size_t _buf_ring_size;
    int _mask;
    char* _entries_base;
    std::unique_ptr<BufferRingEntry> _current_entry;

    std::unique_ptr<rawstor::io::TaskBuffered> _t;

    void* _get_entry(unsigned int index);

public:
    TaskBufferRing(
        io_uring& ring, std::unique_ptr<rawstor::io::TaskBuffered> t
    );
    ~TaskBufferRing();

    void operator()(size_t result, int error) override;

    void select_entry(unsigned int index) noexcept;

    unsigned int id() const noexcept;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_TASK_HPP
