#include "rawstorstd/iovec.h"

#include <sys/uio.h>

#include <stddef.h>


size_t rawstor_iovec_discard_front(
    struct iovec **iov, unsigned int *niov, size_t size)
{
    while (*niov > 0 && size >= (*iov)[0].iov_len) {
        size -= (*iov)[0].iov_len;
        --(*niov);
        ++(*iov);
    }

    if (*niov == 0) {
        return size;
    }

    (*iov)[0].iov_base += size;
    (*iov)[0].iov_len -= size;

    return 0;
}
