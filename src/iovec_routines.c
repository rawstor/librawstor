#include "iovec_routines.h"

#include <sys/uio.h>

#include <stddef.h>


void iovec_shift(struct iovec **iov, unsigned int *niov, size_t shift) {
    while (*niov > 0 && shift >= (*iov)[0].iov_len) {
        shift -= (*iov)[0].iov_len;
        --(*niov);
        ++(*iov);
    }

    if (*niov == 0) {
        return;
    }

    (*iov)[0].iov_base += shift;
    (*iov)[0].iov_len -= shift;
}
