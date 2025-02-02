#ifndef RAWSTOR_CLI_GCC_H
#define RAWSTOR_CLI_GCC_H


#if defined(__GNUC__) && (__GNUC__ >= 3)
#define RAWSTOR_CLI_UNUSED  __attribute__((unused))
#else
#define RAWSTOR_CLI_UNUSED
#endif


#endif // RAWSTOR_CLI_GCC_H
