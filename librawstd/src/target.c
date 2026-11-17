/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#include <rawstd/target.h>
#include <rawstd/uuid.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int is_uuid(const char* s, size_t len) {
    if (len != 36) {
        return 0;
    }
    char buf[37];
    memcpy(buf, s, len);
    buf[len] = '\0';
    struct RawstdUUID uuid;
    return rawstd_uuid_from_string(&uuid, buf) == 0;
}

static int is_hex(const char* s, size_t len) {
    if (len == 0) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

/* UUID, UUID/VERSION_UUID or UUID/HEX_OFFSET. */
static int is_id(const char* s) {
    size_t len = strlen(s);
    if (len == 36) {
        return is_uuid(s, len);
    }
    if (len < 38 || s[36] != '/' || !is_uuid(s, 36)) {
        return 0;
    }
    return is_uuid(s + 37, len - 37) || is_hex(s + 37, len - 37);
}

/* Whether `s` is a location: it has a scheme, and the last URI of the list
 * has no UUID-shaped segment among the last two segments of its path (a
 * target ends with the object id, optionally followed by one more segment). */
static int is_location(const char* s) {
    if (strstr(s, "://") == NULL) {
        return 0;
    }
    const char* uri = s;
    for (const char* p = s; *p != '\0'; ++p) {
        if (*p == '\\' && p[1] != '\0') {
            ++p;
        } else if (*p == ',') {
            uri = p + 1;
        }
    }
    const char* end = uri + strlen(uri);
    for (int i = 0; i < 2 && end > uri; ++i) {
        while (end > uri && end[-1] == '/') {
            --end;
        }
        const char* start = end;
        while (start > uri && start[-1] != '/') {
            --start;
        }
        if (is_uuid(start, (size_t)(end - start))) {
            return 0;
        }
        end = start;
    }
    return 1;
}

/* Appends "/id" to every URI of the comma-separated `location`. */
static char* compose(const char* location, const char* id) {
    size_t id_len = strlen(id);
    size_t cap = strlen(location) + 1;
    for (const char* p = location; *p != '\0'; ++p) {
        if (*p == ',') {
            cap += id_len + 1;
        }
    }
    cap += id_len + 1;
    char* result = malloc(cap + 1);
    if (result == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    char* out = result;
    const char* uri = location;
    for (const char* p = location;; ++p) {
        if (*p == '\\' && p[1] != '\0') {
            ++p;
            continue;
        }
        if (*p != ',' && *p != '\0') {
            continue;
        }
        const char* end = p;
        while (end > uri && end[-1] == '/') {
            --end;
        }
        memcpy(out, uri, (size_t)(end - uri));
        out += end - uri;
        *out++ = '/';
        memcpy(out, id, id_len);
        out += id_len;
        if (*p == '\0') {
            break;
        }
        *out++ = ',';
        uri = p + 1;
    }
    *out = '\0';
    return result;
}

char* rawstd_target_resolve(
    const char* first, const char* second, int* consumed
) {
    *consumed = 1;

    if (is_id(first)) {
        const char* location = getenv("RAWSTOR_LOCATION");
        if (location == NULL || location[0] == '\0') {
            errno = ENOENT;
            return NULL;
        }
        return compose(location, first);
    }

    if (second != NULL && is_id(second) && is_location(first)) {
        *consumed = 2;
        return compose(first, second);
    }

    char* copy = strdup(first);
    if (copy == NULL) {
        errno = ENOMEM;
    }
    return copy;
}
