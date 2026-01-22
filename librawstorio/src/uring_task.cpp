#include "uring_task.hpp"

#include <rawstorstd/gpp.hpp>

#include <sys/mman.h>

#include <cassert>

#include <memory>
#include <new>

namespace {

unsigned int shift(unsigned int value) {
    if (value == 0) {
        return 0;
    }

    unsigned int ret = 0;
    while (value >> ret != 1) {
        ++ret;
    }

    return ret;
}

} // unnamed namespace

namespace rawstor {
namespace io {
namespace uring {

BufferRingEntry::BufferRingEntry(
    io_uring_buf_ring* buf_ring, void* data, size_t size, unsigned int index,
    int mask
) :
    _buf_ring(buf_ring),
    _data(data),
    _size(size),
    _index(index),
    _mask(mask) {
}

BufferRingEntry::~BufferRingEntry() {
    io_uring_buf_ring_add(_buf_ring, _data, _size, _index, _mask, 0);
    io_uring_buf_ring_advance(_buf_ring, 1);
}

__u16 TaskBufferRing::_id_counter = 0;

TaskBufferRing::TaskBufferRing(
    io_uring& ring, std::unique_ptr<rawstor::io::TaskBuffered> t
) :
    _entry_size(t->size()),
    _entry_shift(shift(t->size())),
    _id(++_id_counter),
    _buf_ring(nullptr),
    _buf_ring_size(
        sizeof(struct io_uring_buf) * t->count() + _entry_size * t->count()
    ),
    _mask(io_uring_buf_ring_mask(t->count())),
    _entries_base(nullptr),
    _t(std::move(t)) {

    unsigned int buffers = _t->count();

    assert((_entry_size & (_entry_size - 1)) == 0);
    assert((buffers & (buffers - 1)) == 0);

    _buf_ring = static_cast<io_uring_buf_ring*>(mmap(
        nullptr, _buf_ring_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0
    ));
    if (_buf_ring == MAP_FAILED) {
        throw std::bad_alloc();
    }
    _entries_base =
        reinterpret_cast<char*>(_buf_ring) + sizeof(io_uring_buf) * buffers;

    try {
        io_uring_buf_ring_init(_buf_ring);

        io_uring_buf_reg reg{};
        reg.ring_addr = reinterpret_cast<__u64>(_buf_ring);
        reg.ring_entries = buffers;
        reg.bgid = _id;

        // TODO: Replace with io_uring_setup_buf_ring()?
        int res = io_uring_register_buf_ring(&ring, &reg, 0);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        for (unsigned int i = 0; i < buffers; ++i) {
            io_uring_buf_ring_add(
                _buf_ring, _get_entry(i), _entry_size, i, _mask, i
            );
        }

        // TODO: use io_uring_buf_ring_cq_advance() here?
        io_uring_buf_ring_advance(_buf_ring, buffers);
    } catch (...) {
        munmap(_buf_ring, _buf_ring_size);
        throw;
    }
}

TaskBufferRing::~TaskBufferRing() {
    munmap(_buf_ring, _buf_ring_size);
    // TODO: Add io_uring_free_buf_ring() if we are going to use
    // io_uring_setup_buf_ring()
}

void TaskBufferRing::operator()(size_t result, int error) {
    void* buffer =
        _current_entry.get() != nullptr ? _current_entry->data() : nullptr;
    _t->set(buffer);
    try {
        (*_t)(result, error);
    } catch (...) {
        _t->set(nullptr);
        _current_entry.reset();
        throw;
    }
    _t->set(nullptr);
    _current_entry.reset();
}

void* TaskBufferRing::_get_entry(unsigned int index) {
    return _entries_base + (index << _entry_shift);
}

void TaskBufferRing::select_entry(unsigned int index) noexcept {
    _current_entry = std::make_unique<BufferRingEntry>(
        _buf_ring, _get_entry(index), _entry_size, index, _mask
    );
}

unsigned int TaskBufferRing::id() const noexcept {
    return _id;
}

} // namespace uring
} // namespace io
} // namespace rawstor
