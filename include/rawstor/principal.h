/**
 * Copyright (C) 2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 * SPDX-License-Identifier: LGPL-3.0
 */
#ifndef RAWSTOR_PRINCIPAL_H
#define RAWSTOR_PRINCIPAL_H
#include <rawstor/protocol.h>
#include <rawstor/rawio.h>
#include <stddef.h>
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
struct RawstorPrincipal {
    char identity[RAWSTOR_PRINCIPAL_ID_SIZE];
    char object_id[37]; /* empty for the principal's tenant role */
    unsigned int role;
    unsigned int rights;
};
/* Provider-admin operations on exactly one mds:// location. A null object
 * changes the principal role; otherwise rights restrict this object's access
 * within that role (zero denies it). Changes affect new capabilities; existing
 * capabilities remain usable until expiry. Calls return 0 when submitted or
 * a negative errno. The completion callback receives 0 or a negative errno. */
int rawstor_principal_set(
    RawIOQueue* queue, const char* location, const char* identity,
    unsigned int role, const char* object, unsigned int rights,
    int (*cb)(ssize_t, void*), void* data
) RAWSTOR_NOEXCEPT;
int rawstor_principal_remove(
    RawIOQueue* queue, const char* location, const char* identity,
    const char* object, int (*cb)(ssize_t, void*), void* data
) RAWSTOR_NOEXCEPT;
/* The list includes principal roles and object restrictions. Free the returned
 * array with rawstor_principal_list_delete(). */
int rawstor_principal_list(
    RawIOQueue* queue, const char* location, struct RawstorPrincipal** entries,
    size_t* count, int (*cb)(ssize_t, void*), void* data
) RAWSTOR_NOEXCEPT;
void rawstor_principal_list_delete(
    struct RawstorPrincipal* entries
) RAWSTOR_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#endif
