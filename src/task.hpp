#ifndef RAWSTOR_TASK_HPP
#define RAWSTOR_TASK_HPP

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <sys/uio.h>


namespace rawstor {


class Task {
    private:
        size_t _size;
        RawstorCallback *_cb;
        void *_data;

    public:
        Task(size_t size, RawstorCallback *cb, void *data):
            _size(size),
            _cb(cb),
            _data(data)
        {}
        Task(const Task &) = delete;
        Task(Task &&) = delete;
        virtual ~Task() {}

        Task& operator=(const Task &) = delete;
        Task& operator=(Task &&) = delete;

        virtual void operator()(RawstorObject *o, size_t result, int error) {
            int res = _cb(o, _size, result, error, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        inline size_t size() const noexcept {
            return _size;
        }

        inline RawstorCallback* callback() noexcept {
            return _cb;
        }

        void* data() noexcept {
            return _data;
        }
};


class TaskScalar: public Task {
    private:
        void *_buf;
        off_t _offset;

    public:
        TaskScalar(
            void *buf,
            size_t size,
            off_t offset,
            RawstorCallback *cb,
            void *data):
            Task(size, cb, data),
            _buf(buf),
            _offset(offset)
        {}

        inline void* buf() noexcept {
            return _buf;
        }

        inline off_t offset() const noexcept {
            return _offset;
        }
};


class TaskVector: public Task {
    private:
        iovec *_iov;
        unsigned int _niov;
        off_t _offset;

    public:
        TaskVector(
            iovec *iov,
            unsigned int niov,
            size_t size,
            off_t offset,
            RawstorCallback *cb,
            void *data):
            Task(size, cb, data),
            _iov(iov),
            _niov(niov),
            _offset(offset)
        {}

        inline iovec* iov() noexcept {
            return _iov;
        }

        inline unsigned int niov() const noexcept {
            return _niov;
        }

        inline off_t offset() const noexcept {
            return _offset;
        }
};


} // rawstor

#endif // RAWSTOR_TASK_HPP
