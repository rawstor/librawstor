#ifndef RAWSTOR_LOGGING_H
#define RAWSTOR_LOGGING_H


#define RAWSTOR_LOGLEVEL_NONE 0
#define RAWSTOR_LOGLEVEL_ERROR 1
#define RAWSTOR_LOGLEVEL_WARNING 2
#define RAWSTOR_LOGLEVEL_INFO 3
#define RAWSTOR_LOGLEVEL_DEBUG 4


#define RAWSTOR_LOGLEVEL RAWSTOR_LOGLEVEL_DEBUG


#define rawstor_log(level, ...) do { \
    printf("%s %s:%d ", level, __FILE__, __LINE__); \
    printf(__VA_ARGS__); \
} while(0)


#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_DEBUG
#define rawstor_debug(...) rawstor_log("DEBUG", __VA_ARGS__)
#else
#define rawstor_debug(...) while (0) { rawstor_log("DEBUG", __VA_ARGS__); }
#endif


#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_INFO
#define rawstor_info(...) rawstor_log("INFO", __VA_ARGS__)
#else
#define rawstor_info(...) while (0) { rawstor_log("INFO", __VA_ARGS__); } 
#endif


#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_WARNING
#define rawstor_warning(...) rawstor_log("WARNING", __VA_ARGS__)
#else
#define rawstor_warning(...) while (0) { rawstor_log("WARNING", __VA_ARGS__); }
#endif


#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_ERROR
#define rawstor_error(...) rawstor_log("ERROR", __VA_ARGS__)
#else
#define rawstor_error(...) while (0) { rawstor_log("ERROR", __VA_ARGS__); }
#endif


#endif // RAWSTOR_LOGGING_H
