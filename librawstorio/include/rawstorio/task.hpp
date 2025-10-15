#ifndef RAWSTORIO_TASK_HPP
#define RAWSTORIO_TASK_HPP

#include <rawstor/io_event.h>

#include <sys/uio.h>

namespace rawstor {
namespace io {


class Task {
    public:
        Task() {}
        Task(const Task &) = delete;
        Task(Task &&) = delete;
        virtual ~Task() {}

        Task& operator=(const Task &) = delete;
        Task& operator=(Task &&) = delete;

        virtual void operator()(RawstorIOEvent *event) = 0;
        virtual size_t size() const noexcept = 0;
};


class TaskScalar: public Task {
    public:
        virtual ~TaskScalar() {}

        virtual void* buf() noexcept = 0;
};


class TaskVector: public Task {
    public:
        virtual ~TaskVector() {}

        virtual iovec* iov() noexcept = 0;
        virtual unsigned int niov() const noexcept = 0;
};


class TaskScalarPositional: public TaskScalar {
    public:
        virtual ~TaskScalarPositional() {}

        virtual off_t offset() const noexcept = 0;
};


class TaskVectorPositional: public TaskVector {
    public:
        virtual ~TaskVectorPositional() {}

        virtual off_t offset() const noexcept = 0;
};


}} // rawstor::io

#endif // RAWSTORIO_TASK_HPP
