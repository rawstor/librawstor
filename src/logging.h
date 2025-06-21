#ifndef RAWSTOR_LOGGING_H
#define RAWSTOR_LOGGING_H


#include "config.h"
#include "threading.h"

#include <unistd.h>


#define RAWSTOR_LOGLEVEL_NONE 0
#define RAWSTOR_LOGLEVEL_ERROR 1
#define RAWSTOR_LOGLEVEL_WARNING 2
#define RAWSTOR_LOGLEVEL_INFO 3
#define RAWSTOR_LOGLEVEL_DEBUG 4
#define RAWSTOR_LOGLEVEL_TRACE 5


#if defined(RAWSTOR_CONFIG_ENABLE_TRACE)
#define RAWSTOR_LOGLEVEL RAWSTOR_LOGLEVEL_TRACE
#elif defined(RAWSTOR_CONFIG_ENABLE_DEBUG)
#define RAWSTOR_LOGLEVEL RAWSTOR_LOGLEVEL_DEBUG
#else
#define RAWSTOR_LOGLEVEL RAWSTOR_LOGLEVEL_INFO
#endif


extern RawstorMutex *rawstor_logging_mutex;


void rawstor_logging_initialize(void);

void rawstor_logging_terminate(void);


#define rawstor_log(level, ...) do { \
    rawstor_mutex_lock(rawstor_logging_mutex); \
    rawstor_trace_event_dump(); \
    dprintf(STDERR_FILENO, "%s %s:%d ", level, __FILE__, __LINE__); \
    dprintf(STDERR_FILENO, __VA_ARGS__); \
    rawstor_mutex_unlock(rawstor_logging_mutex); \
} while(0)


#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_TRACE
#define rawstor_trace(...) do { \
    rawstor_log("TRACE", "%s(): ", __FUNCTION__); \
    dprintf(STDERR_FILENO, __VA_ARGS__); \
} while (0)

#define RAWSTOR_TRACE_EVENTS
#else
#define rawstor_trace(...) while (0) { rawstor_log("TRACE", __VA_ARGS__); }
#endif


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


#ifdef RAWSTOR_TRACE_EVENTS
void* rawstor_trace_event_begin(const char *format, ...);

void rawstor_trace_event_end(void* event, const char *format, ...);

void rawstor_trace_event_message(void* event, const char *format, ...);

void rawstor_trace_event_dump(void);
#else
#define rawstor_trace_event_dump()
#endif


#endif // RAWSTOR_LOGGING_H
