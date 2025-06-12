#include "logging.h"

#include "list.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>


#ifdef RAWSTOR_TRACE_EVENTS
typedef enum {
    RAWSTOR_TRACE_EVENT_CREATING,
    RAWSTOR_TRACE_EVENT_AVAILABLE,
    RAWSTOR_TRACE_EVENT_MESSAGE,
    RAWSTOR_TRACE_EVENT_DELETING,
    RAWSTOR_TRACE_EVENT_DELETED,
} RawstorTraceEventType;


static RawstorList *_events_list = NULL;


static RawstorList* _events_list_get(void) {
    return _events_list;
}


static RawstorList* _events_list_create(void);


static RawstorList* (*events_list_get)(void) = _events_list_create;


static RawstorList* _events_list_create(void) {
    _events_list = rawstor_list_create(sizeof(RawstorTraceEventType));
    events_list_get = _events_list_get;
    return _events_list;
}


void* rawstor_trace_event_begin(const char *format, ...) {
    RawstorList *events_list = events_list_get();
    RawstorTraceEventType *iter = rawstor_list_iter(events_list);
    for (; iter != NULL; iter = rawstor_list_next(iter)) {
        if (*iter == RAWSTOR_TRACE_EVENT_DELETED) {
            break;
        }
    }

    if (iter == NULL) {
        iter = rawstor_list_append(events_list);
        if (iter == NULL) {
            return NULL;
        }
    }

    *iter = RAWSTOR_TRACE_EVENT_CREATING;

    rawstor_trace_event_dump();

    printf("TRACE ");

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    return iter;
}


void rawstor_trace_event_end(void *event, const char *format, ...) {
    if (event != NULL) {
        RawstorTraceEventType *iter = event;
        assert(*iter == RAWSTOR_TRACE_EVENT_AVAILABLE);
        *iter = RAWSTOR_TRACE_EVENT_DELETING;
    }

    rawstor_trace_event_dump();

    printf("TRACE ");

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}


void rawstor_trace_event_message(void *event, const char *format, ...) {
    if (event != NULL) {
        RawstorTraceEventType *iter = event;
        assert(*iter == RAWSTOR_TRACE_EVENT_AVAILABLE);
        *iter = RAWSTOR_TRACE_EVENT_MESSAGE;
    }

    rawstor_trace_event_dump();

    printf("TRACE ");

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}


void rawstor_trace_event_dump(void) {
    RawstorList *events_list = events_list_get();
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
        printf("%c ", ch);
    }
}

#endif // RAWSTOR_TRACE_EVENTS
