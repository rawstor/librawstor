#include <rawstor/rawstor.h>

#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>
#include <rawstorio/task.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <memory>
#include <stdexcept>
#include <system_error>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define QUEUE_DEPTH 256

namespace {

class TaskPoll final : public rawstor::io::TaskPoll {
private:
    unsigned int _mask;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskPoll(int fd, unsigned int mask, RawstorIOCallback* cb, void* data) :
        rawstor::io::TaskPoll(fd),
        _mask(mask),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    unsigned int mask() const noexcept override { return _mask; }
};

class TaskScalar final : public rawstor::io::TaskScalar {
private:
    void* _buf;
    size_t _size;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskScalar(
        int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
    ) :
        rawstor::io::TaskScalar(fd),
        _buf(buf),
        _size(size),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    void* buf() noexcept override { return _buf; }

    size_t size() const noexcept override { return _size; }
};

class TaskVector final : public rawstor::io::TaskVector {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskVector(
        int fd, iovec* iov, unsigned int niov, size_t size,
        RawstorIOCallback* cb, void* data
    ) :
        rawstor::io::TaskVector(fd),
        _iov(iov),
        _niov(niov),
        _size(size),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    iovec* iov() noexcept override { return _iov; }

    unsigned int niov() const noexcept override { return _niov; }

    size_t size() const noexcept override { return _size; }
};

class TaskScalarPositional final : public rawstor::io::TaskScalarPositional {
private:
    void* _buf;
    size_t _size;
    off_t _offset;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskScalarPositional(
        int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
        void* data
    ) :
        rawstor::io::TaskScalarPositional(fd),
        _buf(buf),
        _size(size),
        _offset(offset),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    void* buf() noexcept override { return _buf; }

    size_t size() const noexcept override { return _size; }

    off_t offset() const noexcept override { return _offset; }
};

class TaskVectorPositional final : public rawstor::io::TaskVectorPositional {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    off_t _offset;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskVectorPositional(
        int fd, iovec* iov, unsigned int niov, size_t size, off_t offset,
        RawstorIOCallback* cb, void* data
    ) :
        rawstor::io::TaskVectorPositional(fd),
        _iov(iov),
        _niov(niov),
        _size(size),
        _offset(offset),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    iovec* iov() noexcept override { return _iov; }

    unsigned int niov() const noexcept override { return _niov; }

    size_t size() const noexcept override { return _size; }

    off_t offset() const noexcept override { return _offset; }
};

class TaskMessage final : public rawstor::io::TaskMessage {
private:
    msghdr* _msg;
    size_t _size;
    int _flags;

    RawstorIOCallback* _cb;
    void* _data;

public:
    TaskMessage(
        int fd, msghdr* msg, size_t size, int flags, RawstorIOCallback* cb,
        void* data
    ) :
        rawstor::io::TaskMessage(fd),
        _msg(msg),
        _size(size),
        _flags(flags),
        _cb(cb),
        _data(data) {}

    void operator()(size_t result, int error) override {
        int res = _cb(result, error, _data);
        if (res) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    msghdr* msg() noexcept override { return _msg; }

    size_t size() const noexcept override { return _size; }

    int flags() const noexcept override { return _flags; }
};

} // namespace

namespace rawstor {

rawstor::io::Queue* io_queue;

} // namespace rawstor

int rawstor_initialize(const RawstorOpts* opts) {
    int res = 0;

    assert(rawstor::io_queue == nullptr);

    res = rawstor_logging_initialize();
    if (res) {
        goto err_logging_initialize;
    }

    rawstor_info(
        "Rawstor compiled with IO queue engine: %s\n",
        rawstor::io::Queue::engine_name().c_str()
    );

    res = rawstor_opts_initialize(opts);
    if (res) {
        goto err_opts_initialize;
    }

    try {
        std::unique_ptr<rawstor::io::Queue> q =
            rawstor::io::Queue::create(QUEUE_DEPTH);
        rawstor::io_queue = q.get();
        q.release();
    } catch (const std::bad_alloc&) {
        res = -ENOMEM;
        goto err_io_queue;
    }

    return 0;

err_io_queue:
    rawstor_opts_terminate();
err_opts_initialize:
    rawstor_logging_terminate();
err_logging_initialize:
    return res;
}

void rawstor_terminate() {
    delete rawstor::io_queue;
    rawstor_opts_terminate();
    rawstor_logging_terminate();
}

int rawstor_empty1() {
    return rawstor::io_queue->empty1();
}

int rawstor_wait() {
    try {
        rawstor::io_queue->wait(rawstor_opts_wait_timeout());
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
    return 0;
}

int rawstor_fd_poll(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<TaskPoll>(fd, mask, cb, data);
        rawstor::io_queue->poll(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_read(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<TaskScalar>(fd, buf, size, cb, data);
        rawstor::io_queue->read(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_readv(
    int fd, iovec* iov, unsigned int niov, size_t size, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskVector> t =
            std::make_unique<TaskVector>(fd, iov, niov, size, cb, data);
        rawstor::io_queue->read(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_pread(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskScalarPositional> t =
            std::make_unique<TaskScalarPositional>(
                fd, buf, size, offset, cb, data
            );
        rawstor::io_queue->read(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_preadv(
    int fd, iovec* iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback* cb, void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskVectorPositional> t =
            std::make_unique<TaskVectorPositional>(
                fd, iov, niov, size, offset, cb, data
            );
        rawstor::io_queue->read(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_recvmsg(
    int fd, msghdr* msg, size_t size, int flags, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskMessage> t =
            std::make_unique<TaskMessage>(fd, msg, size, flags, cb, data);
        rawstor::io_queue->read(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_write(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<TaskScalar>(fd, buf, size, cb, data);
        rawstor::io_queue->write(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_writev(
    int fd, iovec* iov, unsigned int niov, size_t size, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskVector> t =
            std::make_unique<TaskVector>(fd, iov, niov, size, cb, data);
        rawstor::io_queue->write(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_pwrite(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskScalarPositional> t =
            std::make_unique<TaskScalarPositional>(
                fd, buf, size, offset, cb, data
            );
        rawstor::io_queue->write(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_pwritev(
    int fd, iovec* iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback* cb, void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskVectorPositional> t =
            std::make_unique<TaskVectorPositional>(
                fd, iov, niov, size, offset, cb, data
            );
        rawstor::io_queue->write(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int rawstor_fd_sendmsg(
    int fd, msghdr* msg, size_t size, int flags, RawstorIOCallback* cb,
    void* data
) {
    try {
        std::unique_ptr<rawstor::io::TaskMessage> t =
            std::make_unique<TaskMessage>(fd, msg, size, flags, cb, data);
        rawstor::io_queue->write(std::move(t));
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}
