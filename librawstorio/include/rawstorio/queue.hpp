#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <rawstorio/task.hpp>

#include <memory>
#include <string>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {


class Queue {
    private:
        unsigned int _depth;

    public:
        static const std::string& engine_name();
        static void setup_fd(int fd);
        static std::unique_ptr<Queue> create(unsigned int depth);

        Queue(unsigned int depth): _depth(depth) {}
        Queue(const Queue &) = delete;
        Queue(Queue &&) = delete;
        virtual ~Queue() {}
        Queue& operator=(const Queue &) = delete;
        Queue& operator=(Queue &&) = delete;

        inline unsigned int depth() const noexcept {
            return _depth;
        }

        virtual void poll(std::unique_ptr<TaskPoll> t) = 0;

        virtual void read(std::unique_ptr<TaskScalar> t) = 0;

        virtual void read(std::unique_ptr<TaskVector> t) = 0;

        virtual void read(std::unique_ptr<TaskScalarPositional> t) = 0;

        virtual void read(std::unique_ptr<TaskVectorPositional> t) = 0;

        virtual void read(std::unique_ptr<TaskMessage> t) = 0;

        virtual void write(std::unique_ptr<TaskScalar> t) = 0;

        virtual void write(std::unique_ptr<TaskVector> t) = 0;

        virtual void write(std::unique_ptr<TaskScalarPositional> t) = 0;

        virtual void write(std::unique_ptr<TaskVectorPositional> t) = 0;

        virtual void write(std::unique_ptr<TaskMessage> t) = 0;

        virtual bool empty() const noexcept = 0;

        virtual void wait(unsigned int timeout) = 0;
};


}} // rawstor::io


#endif // RAWSTORIO_QUEUE_HPP
