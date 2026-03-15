#include <rawstor/rawstor.h>

#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

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

namespace rawstor {

rawstor::io::Queue* io_queue;

} // namespace rawstor

int rawstor_initialize(const RawstorOpts* opts) noexcept {
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

void rawstor_terminate() noexcept {
    delete rawstor::io_queue;
    rawstor_opts_terminate();
    rawstor_logging_terminate();
}

int rawstor_wait() noexcept {
    try {
        rawstor::io_queue->wait(rawstor_opts_wait_timeout());
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
    return 0;
}

int rawstor_fd_poll(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->poll(fd, mask, [cb, data](size_t result, int error) {
            int res = cb(result, error, data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        });
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_read(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->read(
            fd, buf, size, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_readv(
    int fd, iovec* iov, unsigned int niov, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->readv(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_pread(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->pread(
            fd, buf, size, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_preadv(
    int fd, iovec* iov, unsigned int niov, off_t offset, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->preadv(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_recv(
    int fd, void* buf, size_t size, unsigned int flags, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->recv(
            fd, buf, size, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_recvmsg(
    int fd, msghdr* msg, unsigned int flags, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->recvmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_write(
    int fd, const void* buf, size_t size, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->write(
            fd, buf, size, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_writev(
    int fd, const iovec* iov, unsigned int niov, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->writev(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_pwrite(
    int fd, const void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->pwrite(
            fd, buf, size, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset,
    RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->pwritev(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_send(
    int fd, const void* buf, size_t size, unsigned int flags,
    RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->send(
            fd, buf, size, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_sendmsg(
    int fd, const msghdr* msg, unsigned int flags, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->sendmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        return -EINVAL;
    }
}
