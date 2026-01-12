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

__u16 TaskBufferRing::_group_id_counter = 0;

TaskBufferRing::TaskBufferRing(
    io_uring& ring, std::unique_ptr<rawstor::io::TaskBuffered> t
) :
    _buffer_shift(shift(t->size())),
    _group_id(++_group_id_counter),
    _buf_ring(nullptr),
    _buf_ring_size(
        sizeof(struct io_uring_buf) * t->count() +
        (1u << _buffer_shift) * t->count()
    ),
    _buf_mask(io_uring_buf_ring_mask(t->count())),
    _buf_base(nullptr),
    _buf_current_index(-1),
    _t(std::move(t)) {

    unsigned int buffer_size = _t->size();
    unsigned int buffers = _t->count();

    assert((buffer_size & (buffer_size - 1)) == 0);
    assert((buffers & (buffers - 1)) == 0);

    _buf_ring = static_cast<io_uring_buf_ring*>(mmap(
        nullptr, _buf_ring_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0
    ));
    if (_buf_ring == MAP_FAILED) {
        throw std::bad_alloc();
    }
    _buf_base =
        reinterpret_cast<char*>(_buf_ring) + sizeof(io_uring_buf) * buffers;

    try {
        io_uring_buf_ring_init(_buf_ring);

        io_uring_buf_reg reg{};
        reg.ring_addr = reinterpret_cast<__u64>(_buf_ring);
        reg.ring_entries = buffers;
        reg.bgid = _group_id;

        // TODO: Replace with io_uring_setup_buf_ring()?
        int res = io_uring_register_buf_ring(&ring, &reg, 0);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        for (unsigned int i = 0; i < buffers; ++i) {
            io_uring_buf_ring_add(
                _buf_ring, _get_buffer(i), 1u << _buffer_shift, i, _buf_mask, i
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
    void* buffer = _buf_current_index != ((unsigned int)-1)
                       ? _get_buffer(_buf_current_index)
                       : nullptr;
    _t->set(buffer);
    try {
        (*_t)(result, error);
    } catch (...) {
        _t->set(nullptr);
        if (buffer != nullptr) {
            io_uring_buf_ring_add(
                _buf_ring, buffer, 1u << _buffer_shift, _buf_current_index,
                _buf_mask, 0
            );
            io_uring_buf_ring_advance(_buf_ring, 1);
        }
        _buf_current_index = -1;
        throw;
    }
    _t->set(nullptr);
    if (buffer != nullptr) {
        io_uring_buf_ring_add(
            _buf_ring, buffer, 1u << _buffer_shift, _buf_current_index,
            _buf_mask, 0
        );
        io_uring_buf_ring_advance(_buf_ring, 1);
    }
    _buf_current_index = -1;
}

char* TaskBufferRing::_get_buffer(unsigned int index) {
    return _buf_base + (index << _buffer_shift);
}

void TaskBufferRing::select_buffer(unsigned int index) noexcept {
    _buf_current_index = index;
}

unsigned int TaskBufferRing::group_id() const noexcept {
    return _group_id;
}

} // namespace uring
} // namespace io
} // namespace rawstor
