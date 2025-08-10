#ifndef RAWSTOR_STD_IOVEC_ROUTINES_H
#define RAWSTOR_STD_IOVEC_ROUTINES_H

#include <sys/uio.h>

#include <stddef.h>


size_t rawstor_iovec_shift(struct iovec **iov, unsigned int *niov, size_t shift);


#endif // RAWSTOR_STD_IOVEC_ROUTINES_H
