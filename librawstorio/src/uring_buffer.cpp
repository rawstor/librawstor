#include "uring_buffer.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <sys/mman.h>

#include <cassert>

#include <bit>
#include <memory>
#include <new>
#include <sstream>
#include <vector>

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
    _result(0),
    _index(index),
    _mask(mask) {
}

BufferRingEntry::~BufferRingEntry() {
    io_uring_buf_ring_add(_buf_ring, _data, _size, _index, _mask, 0);
    io_uring_buf_ring_advance(_buf_ring, 1);
}

__u16 BufferRing::_id_counter = 0;

BufferRing::BufferRing(
    io_uring& ring, size_t entry_size, unsigned int entries,
    std::unique_ptr<rawstor::io::TaskVectorExternal> t
) :
    _entry_size(entry_size),
    _entry_shift(std::countr_zero(entry_size)),
    _id(++_id_counter),
    _buf_ring(nullptr),
    _buf_ring_size(
        sizeof(struct io_uring_buf) * entries + entry_size * entries
    ),
    _mask(io_uring_buf_ring_mask(entries)),
    _entries_base(nullptr),
    _pending_offset(0),
    _pending_size(0),
    _t(std::move(t)) {

    assert((_entry_size & (_entry_size - 1)) == 0);
    assert((entries & (entries - 1)) == 0);

    _buf_ring = static_cast<io_uring_buf_ring*>(mmap(
        nullptr, _buf_ring_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0
    ));
    if (_buf_ring == MAP_FAILED) {
        throw std::bad_alloc();
    }
    _entries_base =
        reinterpret_cast<char*>(_buf_ring) + sizeof(io_uring_buf) * entries;

    try {
        io_uring_buf_ring_init(_buf_ring);

        io_uring_buf_reg reg{};
        reg.ring_addr = reinterpret_cast<__u64>(_buf_ring);
        reg.ring_entries = entries;
        reg.bgid = _id;

        // TODO: Replace with io_uring_setup_buf_ring()?
        int res = io_uring_register_buf_ring(&ring, &reg, 0);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        for (unsigned int i = 0; i < entries; ++i) {
            io_uring_buf_ring_add(
                _buf_ring, _get_entry(i), _entry_size, i, _mask, i
            );
        }

        io_uring_buf_ring_advance(_buf_ring, entries);
    } catch (...) {
        munmap(_buf_ring, _buf_ring_size);
        throw;
    }
}

BufferRing::~BufferRing() {
    munmap(_buf_ring, _buf_ring_size);
    // TODO: Add io_uring_free_buf_ring() if we are going to use
    // io_uring_setup_buf_ring()
}

void BufferRing::operator()(size_t result, int error) {
#ifdef RAWSTOR_TRACE_EVENTS
    std::ostringstream oss;
    oss << "multishot received: result = " << result << ", error = " << error;
    trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
    if (result > 0) {
        _pending_entry->set_result(result);
        _pending_size += result;
        _pending_entries.push_back(std::move(_pending_entry));
    }

    while (_pending_size >= _t->size() || error) {
        std::list<std::unique_ptr<BufferRingEntry>> entries;
        std::vector<iovec> iov;
        size_t iov_size = 0;
        iov.reserve(_pending_entries.size());

        while (!_pending_entries.empty()) {
            BufferRingEntry* e = _pending_entries.front().get();
            void* e_data = static_cast<char*>(e->data()) + _pending_offset;
            size_t e_size = e->result() - _pending_offset;
            if (e_size <= _t->size() - iov_size) [[likely]] {
                iov.push_back({.iov_base = e_data, .iov_len = e_size});
                _pending_offset = 0;
                _pending_size -= e_size;
                entries.push_back(std::move(_pending_entries.front()));
                _pending_entries.pop_front();
                iov_size += e_size;
                if (iov_size == _t->size()) {
                    break;
                }
            } else {
                iov.push_back(
                    {.iov_base = e_data, .iov_len = _t->size() - iov_size}
                );
                _pending_offset += iov.back().iov_len;
                _pending_size -= iov.back().iov_len;
                iov_size += iov.back().iov_len;
                break;
            }
        }

        _t->set(iov.data(), iov.size());
        try {
#ifdef RAWSTOR_TRACE_EVENTS
            std::ostringstream oss;
            oss << "sending iov: niov = " << iov.size()
                << ", size = " << iov_size;
            _t->trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
            (*_t)(iov_size, error);
        } catch (...) {
            _t->set(nullptr, 0);
            throw;
        }
        _t->set(nullptr, 0);

        error = 0;
    }
}

void* BufferRing::_get_entry(unsigned int index) {
    return _entries_base + (index << _entry_shift);
}

void BufferRing::select_entry(unsigned int index) {
    _pending_entry = std::make_unique<BufferRingEntry>(
        _buf_ring, _get_entry(index), _entry_size, index, _mask
    );
}

unsigned int BufferRing::id() const noexcept {
    return _id;
}

} // namespace uring
} // namespace io
} // namespace rawstor
