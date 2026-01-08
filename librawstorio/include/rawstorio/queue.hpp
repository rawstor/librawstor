#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <memory>
#include <string>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {

class TaskPoll;

class TaskScalar;

class TaskVector;

class TaskScalarPositional;

class TaskVectorPositional;

class TaskMessage;

typedef void Event;

class Queue {
private:
    unsigned int _depth;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);
    static std::unique_ptr<Queue> create(unsigned int depth);

    explicit Queue(unsigned int depth);
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    virtual ~Queue() = default;
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    inline unsigned int depth() const noexcept { return _depth; }

    virtual Event* poll(std::unique_ptr<TaskPoll> t) = 0;

    virtual Event* read(std::unique_ptr<TaskScalar> t) = 0;

    virtual Event* read(std::unique_ptr<TaskVector> t) = 0;

    virtual Event* read(std::unique_ptr<TaskScalarPositional> t) = 0;

    virtual Event* read(std::unique_ptr<TaskVectorPositional> t) = 0;

    virtual Event* read(std::unique_ptr<TaskMessage> t) = 0;

    virtual Event* write(std::unique_ptr<TaskScalar> t) = 0;

    virtual Event* write(std::unique_ptr<TaskVector> t) = 0;

    virtual Event* write(std::unique_ptr<TaskScalarPositional> t) = 0;

    virtual Event* write(std::unique_ptr<TaskVectorPositional> t) = 0;

    virtual Event* write(std::unique_ptr<TaskMessage> t) = 0;

    virtual bool empty() const noexcept = 0;

    virtual void wait(unsigned int timeout) = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_QUEUE_HPP
