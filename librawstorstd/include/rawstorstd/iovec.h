#ifndef RAWSTORSTD_IOVEC_ROUTINES_H
#define RAWSTORSTD_IOVEC_ROUTINES_H

#include <sys/uio.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t rawstor_iovec_discard_front(
    struct iovec** iov, unsigned int* niov, size_t size
);

size_t
rawstor_iovec_discard_back(struct iovec** iov, unsigned int* niov, size_t size);

size_t rawstor_iovec_from_buf(
    struct iovec* iov, unsigned int niov, size_t offset, const void* buf,
    size_t size
);

size_t rawstor_iovec_to_buf(
    struct iovec* iov, unsigned int niov, size_t offset, void* buf, size_t size
);

size_t rawstor_iovec_size(struct iovec* iov, unsigned int niov);

#ifdef __cplusplus
}
#endif

#endif // RAWSTORSTD_IOVEC_ROUTINES_H
