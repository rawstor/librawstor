#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * UUID
 */
typedef struct {
    uint8_t bytes[16];
} RawstorUUID;

typedef char RawstorUUIDString[37];


int rawstor_uuid_from_string(RawstorUUID *uuid, const char *s);

void rawstor_uuid_to_string(const RawstorUUID *uuid, RawstorUUIDString *s);


/**
 * IO
 */

typedef struct RawstorIOEvent RawstorIOEvent;

typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);


/**
 * fd
 */

int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_readv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_preadv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);


/**
 * Lib
 */

typedef struct {
    char *host;
    unsigned int port;
    unsigned int so_sndtimeo;
    unsigned int so_rcvtimeo;
    unsigned int tcp_user_timeout;
} RawstorOptsOST;


int rawstor_initialize(const RawstorOptsOST *opts_ost);

void rawstor_terminate(void);

RawstorIOEvent* rawstor_wait_event(void);

RawstorIOEvent* rawstor_wait_event_timeout(int timeout);

int rawstor_dispatch_event(RawstorIOEvent *event);

void rawstor_release_event(RawstorIOEvent *event);


/**
 * Object
 */

typedef struct RawstorObject RawstorObject;

typedef struct {
    size_t size;
} RawstorObjectSpec;

typedef int(RawstorCallback)(
    RawstorObject *object, size_t size, size_t res, int error, void *data);


int rawstor_object_create(
    const RawstorOptsOST *opts_ost,
    const RawstorObjectSpec *spec,
    RawstorUUID *object_id);

int rawstor_object_delete(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id);

int rawstor_object_open(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id,
    RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id,
    RawstorObjectSpec *spec);

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


#endif // RAWSTOR_RAWSTOR_H
