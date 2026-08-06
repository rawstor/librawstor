noinst_LTLIBRARIES = libvduse.la


AM_CFLAGS = -std=gnu99 -Wall -Wextra \
            $(ASAN_CFLAGS)

AM_LDFLAGS = $(ASAN_LDFLAGS)


libvduse_la_SOURCES = include/atomic.h \
                      include/compiler.h \
                      linux-headers/linux/vduse.h \
                      linux-headers/linux/virtio_config.h \
                      linux-headers/linux/virtio_ring.h \
                      standard-headers/linux/types.h \
                      standard-headers/linux/virtio_blk.h \
                      standard-headers/linux/virtio_config.h \
                      standard-headers/linux/virtio_ids.h \
                      standard-headers/linux/virtio_ring.h \
                      standard-headers/linux/virtio_types.h \
                      libvduse.c \
                      libvduse.h

libvduse_la_LIBADD =
