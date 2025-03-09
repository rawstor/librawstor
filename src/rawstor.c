#include <rawstor.h>

#include "io.h"
#include "logging.h"
#include "object.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define QUEUE_DEPTH 256


static RawstorConfig _rawstor_config = {
    .ost_host = NULL,
    .ost_port = 0,
};

static RawstorIO *_rawstor_io = NULL;


static char* config_string(const char *value, const char *default_value) {
    const char *src = value != NULL ? value : default_value;
    assert(value != NULL);

    size_t size = strlen(src) + 1;
    char *dst = malloc(size);
    if (dst == NULL) {
        return NULL;
    }

    memcpy(dst, src, size);

    return dst;
}


static int config_init(RawstorConfig *config, const RawstorConfig *reference) {
    config->ost_host = config_string(
        reference != NULL ? reference->ost_host : NULL, "127.0.0.1");
    if (config->ost_host == NULL) {
        return -errno;
    }

    config->ost_port = reference != NULL ? reference->ost_port : 8080;

    return 0;
}


static void config_release(RawstorConfig *config) {
    free(config->ost_host);
}


int rawstor_initialize(const RawstorConfig *config) {
    assert(_rawstor_io == NULL);

    rawstor_info(
        "Rawstor compiled with IO engine: %s\n",
        rawstor_io_engine_name);

    rawstor_info(
        "Rawstor compiled with object backend: %s\n",
        rawstor_object_backend_name);

    if (config_init(&_rawstor_config, config)) {
        return -errno;
    }

    _rawstor_io = rawstor_io_create(QUEUE_DEPTH);
    if (_rawstor_io == NULL) {
        config_release(&_rawstor_config);
        return -errno;
    };

    return 0;
}


void rawstor_terminate(void) {
    rawstor_io_delete(_rawstor_io);
    config_release(&_rawstor_config);
}


const RawstorConfig* rawstor_config(void) {
    return &_rawstor_config;
}


RawstorIOEvent* rawstor_wait_event(void) {
    return rawstor_io_wait_event(_rawstor_io);
}


RawstorIOEvent* rawstor_wait_event_timeout(int timeout) {
    return rawstor_io_wait_event_timeout(_rawstor_io, timeout);
}


int rawstor_dispatch_event(RawstorIOEvent *event) {
    return rawstor_io_event_dispatch(event);
}


void rawstor_release_event(RawstorIOEvent *event) {
    rawstor_io_release_event(_rawstor_io, event);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_read(
        _rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pread(
        _rawstor_io,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_readv(
        _rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_preadv(
        _rawstor_io,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_recv(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_recv(
        _rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_recvv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_recvv(
        _rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_write(
        _rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pwrite(
        _rawstor_io,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_writev(
        _rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pwritev(
        _rawstor_io,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_send(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_send(
        _rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_sendv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_sendv(
        _rawstor_io,
        fd, iov, niov, size,
        cb, data);
}
