#ifndef RAWSTORIO_URING_TASK_HPP
#define RAWSTORIO_URING_TASK_HPP

#include <rawstorio/task.hpp>

#include <liburing.h>

#include <memory>

namespace rawstor {
namespace io {
namespace uring {

class TaskBufferRing final : public rawstor::io::Task {
private:
    static __u16 _group_id_counter;

    const unsigned int _buffer_shift;

    const __u16 _group_id;
    io_uring_buf_ring* _buf_ring;
    size_t _buf_ring_size;
    int _buf_mask;
    char* _buf_base;
    unsigned int _buf_current_index;

    std::unique_ptr<rawstor::io::TaskBuffered> _t;

    char* _get_buffer(unsigned int index);

public:
    TaskBufferRing(
        io_uring& ring, std::unique_ptr<rawstor::io::TaskBuffered> t
    );
    ~TaskBufferRing();

    void operator()(size_t result, int error) override;

    void select_buffer(unsigned int index) noexcept;

    unsigned int group_id() const noexcept;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_TASK_HPP
