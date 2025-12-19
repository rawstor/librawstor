#include "rawstorstd/iovec.h"

#include <sys/uio.h>

#include <stddef.h>


size_t rawstor_iovec_discard_front(
    struct iovec **iov, unsigned int *niov, size_t size)
{
    size_t total = 0;

    while (*niov > 0 && size >= (*iov)[0].iov_len) {
        size -= (*iov)[0].iov_len;
        total += (*iov)[0].iov_len;
        --(*niov);
        ++(*iov);
    }

    if (*niov != 0) {
        (*iov)[0].iov_base += size;
        (*iov)[0].iov_len -= size;
        total += size;
    }

    return total;
}


size_t rawstor_iovec_discard_back(
    struct iovec **iov, unsigned int *niov, size_t size)
{
    size_t total = 0;

    while (*niov > 0 && size >= (*iov)[*niov - 1].iov_len) {
        size -= (*iov)[*niov - 1].iov_len;
        total += (*iov)[*niov - 1].iov_len;
        --(*niov);
    }

    if (*niov != 0) {
        (*iov)[*niov - 1].iov_len -= size;
        total += size;
    }

    return total;
}
