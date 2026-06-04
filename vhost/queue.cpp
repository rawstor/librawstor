#include "queue.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/rawio.h>

#include <unistd.h>

#include <exception>
#include <stdexcept>

#include <cerrno>
#include <cstring>

namespace {

int callback(size_t result, int error, void* data) noexcept {
    std::unique_ptr<std::function<void()>> cb(
        static_cast<std::function<void()>*>(data)
    );

    if (error == ECANCELED) {
        return 0;
    }

    if (error) {
        return -error;
    }

    if (result != sizeof(int)) {
        return -EPROTO;
    }

    try {
        (*cb)();
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }

    cb.release();

    return 0;
}

} // unnamed namespace

namespace rawstor {
namespace vhost {

class Message {
public:
    virtual ~Message() = default;

    virtual void operator()() = 0;
};

Queue::Queue(unsigned int size) :
    _size(size),
    _pipe_out(-1),
    _pipe_in(-1) {
    int fds[2];
    int res = pipe(fds);
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    _pipe_out = fds[0];
    _pipe_in = fds[1];
    _thread = std::make_unique<std::thread>(Queue::_main, this);
}

Queue::~Queue() {
    _break();
    _thread->join();
    close(_pipe_in);
    if (_pipe_out != -1) {
        close(_pipe_out);
    }
}

void Queue::_main(Queue* queue) {
    queue->_loop();
}

void Queue::_loop() {
    RawIOQueue* queue;
    RawIOEvent* poll_event = nullptr;
    int res = rawio_queue_create(_size, &queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        {
            auto cb = std::make_unique<std::function<void()>>([this]() {
                int data;

                ssize_t result = read(_pipe_out, &data, sizeof(data));
                if (result == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                if (result != sizeof(data)) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
                }

                {
                    std::unique_lock lock(_mutex);
                    while (!_messages.empty()) {
                        std::unique_ptr<Message> m =
                            std::move(_messages.front());
                        _messages.pop_front();
                        (*m)();
                    }
                }
            });
            res = rawio_poll_multishot(
                queue, _pipe_out, POLL_IN, callback, cb.get(), &poll_event
            );
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            cb.release();
        }

        while (true) {
            res = rawio_wait(queue);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }
    } catch (...) {
        if (poll_event != nullptr) {
            res = rawio_cancel(queue, poll_event);
            if (res < 0) {
                rawstd_warning("%s\n", strerror(-res));
            }
        }
        rawio_queue_delete(queue);
        throw;
    }

    rawio_queue_delete(queue);
}

void Queue::_break() {
    if (_pipe_out != -1) {
        close(_pipe_out);
        _pipe_out = -1;
    }
}

} // namespace vhost
} // namespace rawstor
