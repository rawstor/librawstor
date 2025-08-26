#ifndef RAWSTORSTD_IOVEC_ROUTINES_H
#define RAWSTORSTD_IOVEC_ROUTINES_H

#include <sys/uio.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


size_t rawstor_iovec_shift(struct iovec **iov, unsigned int *niov, size_t shift);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORSTD_IOVEC_ROUTINES_H
