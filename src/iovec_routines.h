#ifndef RAWSTOR_IOVEC_ROUTINES_H
#define RAWSTOR_IOVEC_ROUTINES_H

#include <sys/uio.h>

#include <stddef.h>


void iovec_shift(struct iovec **iov, unsigned int *niov, size_t shift);


#endif // RAWSTOR_IOVEC_ROUTINES_H
