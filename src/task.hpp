#ifndef RAWSTOR_TASK_HPP
#define RAWSTOR_TASK_HPP

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <sys/uio.h>


namespace rawstor {


class Task {
    protected:
        RawstorObject *_o;
        size_t _size;
        RawstorCallback *_cb;
        void *_data;

    public:
        explicit Task(
            RawstorObject *o,
            size_t size,
            RawstorCallback *cb,
            void *data):
            _o(o),
            _size(size),
            _cb(cb),
            _data(data)
        {}
        Task(const Task &) = delete;
        Task(Task &&) = delete;
        virtual ~Task() {}

        Task& operator=(const Task &) = delete;
        Task& operator=(Task &&) = delete;

        inline size_t size() const noexcept {
            return _size;
        }

        virtual void operator()(size_t result, int error) {
            int res = _cb(_o, _size, result, error, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }
};


} // rawstor

#endif // RAWSTOR_TASK_HPP
