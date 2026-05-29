#ifndef RAWSTD_LOGGING_H
#define RAWSTD_LOGGING_H

#include <rawstd/logging_config.h>
#include <rawstd/threading.h>

#include <stdio.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

extern RawstdMutex* rawstd_logging_mutex;

int rawstd_logging_initialize(void);

void rawstd_logging_terminate(void);

#define rawstd_log(level, ...)                                                 \
    do {                                                                       \
        rawstd_mutex_lock(rawstd_logging_mutex);                               \
        rawstd_trace_event_dump();                                             \
        dprintf(STDERR_FILENO, "%s %s:%d ", level, __FILE__, __LINE__);        \
        dprintf(STDERR_FILENO, __VA_ARGS__);                                   \
        rawstd_mutex_unlock(rawstd_logging_mutex);                             \
    } while (0)

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_TRACE
#define rawstd_trace(...)                                                      \
    do {                                                                       \
        rawstd_log("TRACE", "%s(): ", __FUNCTION__);                           \
        dprintf(STDERR_FILENO, __VA_ARGS__);                                   \
    } while (0)

#define RAWSTD_TRACE_EVENTS
#else
#define rawstd_trace(...)                                                      \
    while (0) {                                                                \
        rawstd_log("TRACE", __VA_ARGS__);                                      \
    }
#endif

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_DEBUG
#define rawstd_debug(...) rawstd_log("DEBUG", __VA_ARGS__)
#else
#define rawstd_debug(...)                                                      \
    while (0) {                                                                \
        rawstd_log("DEBUG", __VA_ARGS__);                                      \
    }
#endif

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_INFO
#define rawstd_info(...) rawstd_log("INFO", __VA_ARGS__)
#else
#define rawstd_info(...)                                                       \
    while (0) {                                                                \
        rawstd_log("INFO", __VA_ARGS__);                                       \
    }
#endif

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_WARNING
#define rawstd_warning(...) rawstd_log("WARNING", __VA_ARGS__)
#else
#define rawstd_warning(...)                                                    \
    while (0) {                                                                \
        rawstd_log("WARNING", __VA_ARGS__);                                    \
    }
#endif

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_ERROR
#define rawstd_error(...) rawstd_log("ERROR", __VA_ARGS__)
#else
#define rawstd_error(...)                                                      \
    while (0) {                                                                \
        rawstd_log("ERROR", __VA_ARGS__);                                      \
    }
#endif

#ifdef RAWSTD_TRACE_EVENTS
size_t rawstd_trace_event_va_begin(
    char appearance, const char* file, int line, const char* function,
    const char* format, va_list ap
);

size_t rawstd_trace_event_begin(
    char appearance, const char* file, int line, const char* function,
    const char* format, ...
);

void rawstd_trace_event_inc(size_t event);

void rawstd_trace_event_dec(size_t event);

void rawstd_trace_event_va_message(
    size_t event, const char* file, int line, const char* function,
    const char* format, va_list ap
);

void rawstd_trace_event_message(
    size_t event, const char* file, int line, const char* function,
    const char* format, ...
);

void rawstd_trace_event_dump(void);
#else
#define rawstd_trace_event_dump()
#endif

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_LOGGING_H
