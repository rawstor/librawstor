#ifndef RAWSTOR_LOGGING_H
#define RAWSTOR_LOGGING_H


#define RAWSTOR_LOGLEVEL 3

#if RAWSTOR_LOGLEVEL > 3
#define rawstor_debug(...) printf(__VA_ARGS__)
#else
#define rawstor_debug(...)
#endif

#if RAWSTOR_LOGLEVEL > 2
#define rawstor_info(...) printf(__VA_ARGS__)
#else
#define rawstor_info(...)
#endif


#endif // RAWSTOR_LOGGING_H
