#ifndef RAWSTORIO_TASK_HPP
#define RAWSTORIO_TASK_HPP

#include <rawstor/io_event.h>

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
};


}} // rawstor::io

#endif // RAWSTORIO_TASK_HPP
