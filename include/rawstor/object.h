/**
 * Copyright (C) 2025, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

#include <rawstor/rawstor.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorObject RawstorObject;

struct RawstorObjectSpec {
    size_t size;
};

typedef int(RawstorCallback)(
    RawstorObject *object, size_t size, size_t result, int error, void *data);


int rawstor_object_spec(
    const char *object_uris,
    struct RawstorObjectSpec *spec);

int rawstor_object_create(
    const char *uris,
    const struct RawstorObjectSpec *spec,
    char *object_uris, size_t size);

int rawstor_object_remove(const char *object_uris);

int rawstor_object_open(
    const char *object_uris,
    RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

void rawstor_object_id(const RawstorObject *object, char **buf);

int rawstor_object_uris(const RawstorObject *object, char *buf, size_t size);

int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_OBJECT_H
