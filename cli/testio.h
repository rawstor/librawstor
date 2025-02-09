#ifndef RAWSTOR_CLI_TESTIO_H
#define RAWSTOR_CLI_TESTIO_H

#include <stddef.h>


int rawstor_cli_testio(
    int object_id,
    size_t block_size, unsigned int count, unsigned int io_depth,
    int vector_mode);


#endif // RAWSTOR_CLI_TESTIO_H
