#include "rawstorstd/logging.h"

#include "rawstorstd/list.h"
#include "rawstorstd/threading.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


RawstorMutex *rawstor_logging_mutex = NULL;


#ifdef RAWSTOR_TRACE_EVENTS

typedef enum {
    RAWSTOR_TRACE_EVENT_CREATING,
    RAWSTOR_TRACE_EVENT_AVAILABLE,
    RAWSTOR_TRACE_EVENT_MESSAGE,
    RAWSTOR_TRACE_EVENT_DELETING,
    RAWSTOR_TRACE_EVENT_DELETED,
} RawstorTraceEventType;


static RawstorList *events_list = NULL;

#endif // RAWSTOR_TRACE_EVENTS


int rawstor_logging_initialize(void) {
    int ret = 0;

    rawstor_logging_mutex = rawstor_mutex_create();
    if (rawstor_logging_mutex == NULL) {
        ret = errno;
        errno = 0;
        goto err_mutex;
    }

#ifdef RAWSTOR_TRACE_EVENTS
    events_list = rawstor_list_create(sizeof(RawstorTraceEventType));
    if (events_list == NULL) {
        ret = errno;
        errno = 0;
        goto err_events_list;
    }
#endif // RAWSTOR_TRACE_EVENTS

    return ret;

#ifdef RAWSTOR_TRACE_EVENTS
err_events_list:
    rawstor_mutex_delete(rawstor_logging_mutex);
#endif // RAWSTOR_TRACE_EVENTS
err_mutex:
    return -ret;
}


void rawstor_logging_terminate(void) {
    rawstor_mutex_delete(rawstor_logging_mutex);
}


#ifdef RAWSTOR_TRACE_EVENTS


void* rawstor_trace_event_begin(const char *format, ...) {
    rawstor_mutex_lock(rawstor_logging_mutex);

    RawstorTraceEventType *iter = rawstor_list_iter(events_list);
    for (; iter != NULL; iter = rawstor_list_next(iter)) {
        if (*iter == RAWSTOR_TRACE_EVENT_DELETED) {
            break;
        }
    }

    if (iter == NULL) {
        iter = rawstor_list_append(events_list);
        if (iter == NULL) {
            rawstor_mutex_unlock(rawstor_logging_mutex);
            return NULL;
        }
    }

    *iter = RAWSTOR_TRACE_EVENT_CREATING;

    rawstor_trace_event_dump();

    dprintf(STDERR_FILENO, "TRACE ");

    va_list args;
    va_start(args, format);
    vdprintf(STDERR_FILENO, format, args);
    va_end(args);

    rawstor_mutex_unlock(rawstor_logging_mutex);
    return iter;
}


void rawstor_trace_event_end(void *event, const char *format, ...) {
    rawstor_mutex_lock(rawstor_logging_mutex);

    if (event != NULL) {
        RawstorTraceEventType *iter = event;
        assert(*iter == RAWSTOR_TRACE_EVENT_AVAILABLE);
        *iter = RAWSTOR_TRACE_EVENT_DELETING;
    }

    rawstor_trace_event_dump();

    dprintf(STDERR_FILENO, "TRACE ");

    va_list args;
    va_start(args, format);
    vdprintf(STDERR_FILENO, format, args);
    va_end(args);

    rawstor_mutex_unlock(rawstor_logging_mutex);
}


void rawstor_trace_event_message(void *event, const char *format, ...) {
    rawstor_mutex_lock(rawstor_logging_mutex);

    if (event != NULL) {
        RawstorTraceEventType *iter = event;
        assert(*iter == RAWSTOR_TRACE_EVENT_AVAILABLE);
        *iter = RAWSTOR_TRACE_EVENT_MESSAGE;
    }

    rawstor_trace_event_dump();

    dprintf(STDERR_FILENO, "TRACE ");

    va_list args;
    va_start(args, format);
    vdprintf(STDERR_FILENO, format, args);
    va_end(args);

    rawstor_mutex_unlock(rawstor_logging_mutex);
}


void rawstor_trace_event_dump(void) {
    for (
        RawstorTraceEventType *iter = rawstor_list_iter(events_list);
        iter != NULL;
        iter = rawstor_list_next(iter))
    {
        char ch = '?';
        switch (*iter) {
            case RAWSTOR_TRACE_EVENT_CREATING:
                ch = '+';
                *iter = RAWSTOR_TRACE_EVENT_AVAILABLE;
                break;
            case RAWSTOR_TRACE_EVENT_AVAILABLE:
                ch = '|';
                break;
            case RAWSTOR_TRACE_EVENT_MESSAGE:
                ch = '*';
                *iter = RAWSTOR_TRACE_EVENT_AVAILABLE;
                break;
            case RAWSTOR_TRACE_EVENT_DELETING:
                ch = '-';
                *iter = RAWSTOR_TRACE_EVENT_DELETED;
                break;
            case RAWSTOR_TRACE_EVENT_DELETED:
                ch = ' ';
                break;
        }
        dprintf(STDERR_FILENO, "%c ", ch);
    }
}


#endif // RAWSTOR_TRACE_EVENTS
