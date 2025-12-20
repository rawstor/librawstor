#include "rawstorstd/iovec.h"

#include <sys/uio.h>

#include <stddef.h>
#include <string.h>


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


size_t rawstor_iovec_to_buf(
    struct iovec *iov, unsigned int niov, size_t offset,
    void *buf, size_t size)
{
    size_t total = 0;

    for (unsigned int i = 0; (offset || size) && i < niov; i++) {
        if (offset < iov[i].iov_len) {
            size_t len = iov[i].iov_len - offset < size ?
                iov[i].iov_len - offset : size;
            memcpy(buf + total, iov[i].iov_base + offset, len);
            size -= len;
            total += len;
            offset = 0;
        } else {
            offset -= iov[i].iov_len;
        }
    }

    return total;
}


size_t rawstor_iovec_size(struct iovec *iov, unsigned int niov) {
    size_t ret = 0;

    for (unsigned int i = 0; i < niov; i++) {
        ret += iov[i].iov_len;
    }

    return ret;
}
