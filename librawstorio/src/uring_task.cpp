#include "uring_task.hpp"

#include <rawstorstd/gpp.hpp>

#include <sys/mman.h>

#include <memory>
#include <new>

#define BUFFERS (64 * 4) // Must be power of two less or equal than 32768
#define BUFFER_SHIFT 17
#define BUFFER_SIZE (1u << BUFFER_SHIFT)

namespace rawstor {
namespace io {
namespace uring {

__u16 TaskBufferRing::_group_id_counter = 0;

TaskBufferRing::TaskBufferRing(
    io_uring& ring, std::unique_ptr<rawstor::io::TaskBuffered> t
) :
    _group_id(++_group_id_counter),
    _buf_ring(nullptr),
    _buf_ring_size(
        sizeof(struct io_uring_buf) * BUFFERS + BUFFER_SIZE * BUFFERS
    ),
    _buf_base(nullptr),
    _t(std::move(t)) {

    _buf_ring = static_cast<io_uring_buf_ring*>(mmap(
        nullptr, _buf_ring_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0
    ));
    if (_buf_ring == MAP_FAILED) {
        throw std::bad_alloc();
    }
    _buf_base =
        reinterpret_cast<char*>(_buf_ring) + sizeof(io_uring_buf) * BUFFERS;

    try {
        io_uring_buf_ring_init(_buf_ring);

        io_uring_buf_reg reg{};
        reg.ring_addr = reinterpret_cast<__u64>(_buf_ring);
        reg.ring_entries = BUFFERS;
        reg.bgid = _group_id;

        // TODO: Replace with io_uring_setup_buf_ring()?
        int res = io_uring_register_buf_ring(&ring, &reg, 0);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        int mask = io_uring_buf_ring_mask(BUFFERS);
        for (unsigned int i = 0; i < BUFFERS; ++i) {
            io_uring_buf_ring_add(
                _buf_ring, _get_buffer(i), BUFFER_SIZE, i, mask, i
            );
        }

        // TODO: use io_uring_buf_ring_cq_advance() here?
        io_uring_buf_ring_advance(_buf_ring, BUFFERS);
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
    (*_t)(result, error);
}

char* TaskBufferRing::_get_buffer(unsigned int index) {
    return _buf_base + (index << BUFFER_SHIFT);
}

void TaskBufferRing::select_buffer(unsigned int index) noexcept {
    _t->set_buffer(_get_buffer(index));
}

__u16 TaskBufferRing::group_id() const noexcept {
    return _group_id;
}

} // namespace uring
} // namespace io
} // namespace rawstor
