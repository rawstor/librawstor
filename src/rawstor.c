#include <rawstor.h>

#include <sys/uio.h>

#include <stddef.h>



int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf)
{
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = size,
    };

    return rawstor_readv(device, offset, size, &iov, 1);
}


int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf)
{
    const struct iovec iov = {
        .iov_base = (void*)buf,
        .iov_len = size,
    };

    return rawstor_writev(device, offset, size, &iov, 1);
}
