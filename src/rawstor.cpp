#include <rawstor/rawstor.h>

#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

#include <rawio/queue.hpp>

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

namespace rawstor {

rawio::Queue* io_queue;

} // namespace rawstor

int rawstor_initialize(const RawstorOpts* opts) noexcept {
    try {
        int res = 0;

        assert(rawstor::io_queue == nullptr);

        res = rawstd_logging_initialize();
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        rawstd_info(
            "Rawstor compiled with IO queue engine: %s\n",
            rawio::Queue::engine_name().c_str()
        );

        res = rawstor_opts_initialize(opts);
        if (res) {
            rawstd_logging_terminate();
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        try {
            std::unique_ptr<rawio::Queue> q =
                rawio::Queue::create(rawstor_opts_queue_depth());
            rawstor::io_queue = q.get();
            q.release();
        } catch (...) {
            rawstd_logging_terminate();
            rawstor_opts_terminate();
            throw;
        }

        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_empty() noexcept {
    try {
        return rawstor::io_queue->empty();
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

void rawstor_terminate() noexcept {
    try {
        delete rawstor::io_queue;
        rawstor::io_queue = nullptr;
        rawstor_opts_terminate();
        rawstd_logging_terminate();
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    } catch (...) {
        rawstd_error("Unexpected error\n");
    }
}

int rawstor_wait() noexcept {
    try {
        rawstor::io_queue->wait_timeout(rawstor_opts_wait_timeout());
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_poll(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->poll(fd, mask, [cb, data](size_t result, int error) {
            int res = cb(result, error, data);
            if (res) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        });
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
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
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_readv(
    int fd, iovec* iov, unsigned int niov, size_t, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->readv(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
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
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_preadv(
    int fd, iovec* iov, unsigned int niov, size_t, off_t offset,
    RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->preadv(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_recvmsg(
    int fd, msghdr* msg, size_t, int flags, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->recvmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_write(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->write(
            fd, buf, size, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_writev(
    int fd, iovec* iov, unsigned int niov, size_t, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->writev(
            fd, iov, niov, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_pwrite(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) noexcept {
    try {
        rawstor::io_queue->pwrite(
            fd, buf, size, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_pwritev(
    int fd, iovec* iov, unsigned int niov, size_t, off_t offset,
    RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->pwritev(
            fd, iov, niov, offset, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_fd_sendmsg(
    int fd, msghdr* msg, size_t, int flags, RawstorIOCallback* cb, void* data
) noexcept {
    try {
        rawstor::io_queue->sendmsg(
            fd, msg, flags, [cb, data](size_t result, int error) {
                int res = cb(result, error, data);
                if (res) {
                    RAWSTD_THROW_SYSTEM_ERROR(-res);
                }
            }
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
