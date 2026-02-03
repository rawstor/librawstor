#include "rawstorstd/iovec.h"

#include <sys/uio.h>

#include <stddef.h>
#include <string.h>

size_t rawstor_iovec_discard_front(
    struct iovec** iov, unsigned int* niov, size_t size
) {
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
    struct iovec** iov, unsigned int* niov, size_t size
) {
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

size_t rawstor_iovec_from_buf(
    struct iovec* iov, unsigned int niov, size_t offset, const void* buf,
    size_t size
) {
    size_t total = 0;

    for (unsigned int i = 0; (offset || size) && i < niov; i++) {
        if (offset < iov[i].iov_len) {
            size_t len =
                iov[i].iov_len - offset < size ? iov[i].iov_len - offset : size;
            memcpy(iov[i].iov_base + offset, buf + total, len);
            size -= len;
            total += len;
            offset = 0;
        } else {
            offset -= iov[i].iov_len;
        }
    }

    return total;
}

size_t rawstor_iovec_to_buf(
    struct iovec* iov, unsigned int niov, size_t offset, void* buf, size_t size
) {
    size_t total = 0;

    for (unsigned int i = 0; (offset || size) && i < niov; i++) {
        if (offset < iov[i].iov_len) {
            size_t len =
                iov[i].iov_len - offset < size ? iov[i].iov_len - offset : size;
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

size_t rawstor_iovec_to_iovec(
    struct iovec* src_iov, unsigned int src_niov, size_t offset,
    struct iovec* dst_iov, unsigned int dst_niov
) {
    if (!src_niov || !dst_niov) {
        return 0;
    }

    size_t total = 0;
    unsigned int i = 0;
    size_t src_pos = 0;

    while (i < src_niov && offset > 0) {
        size_t size = src_iov[i].iov_len;

        if (offset >= size) {
            offset -= size;
            i++;
        } else {
            src_pos = offset;
            offset = 0;
            break;
        }
    }

    if (i >= src_niov) {
        return 0;
    }

    unsigned int j = 0;
    size_t dst_pos = 0;

    while (i < src_niov && j < dst_niov) {
        void* src_ptr = src_iov[i].iov_base + src_pos;
        size_t src_remaining = src_iov[i].iov_len - src_pos;

        void* dst_ptr = dst_iov[j].iov_base + dst_pos;
        size_t dst_remaining = dst_iov[j].iov_len - dst_pos;

        size_t size =
            src_remaining < dst_remaining ? src_remaining : dst_remaining;

        if (size == 0) {
            break;
        }

        memcpy(dst_ptr, src_ptr, size);
        total += size;

        src_pos += size;
        if (src_pos >= src_iov[i].iov_len) {
            i++;
            src_pos = 0;
        }

        dst_pos += size;
        if (dst_pos >= dst_iov[j].iov_len) {
            j++;
            dst_pos = 0;
        }
    }

    return total;
}

size_t rawstor_iovec_size(struct iovec* iov, unsigned int niov) {
    size_t ret = 0;

    for (unsigned int i = 0; i < niov; i++) {
        ret += iov[i].iov_len;
    }

    return ret;
}
