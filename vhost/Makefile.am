bin_PROGRAMS = rawstor-vhost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_vhost_SOURCES = stdheaders/linux/types.h \
                        stdheaders/linux/vhost_types.h \
                        stdheaders/linux/virtio_blk.h \
                        stdheaders/linux/virtio_config.h \
                        stdheaders/linux/virtio_ring.h \
                        stdheaders/linux/virtio_types.h \
                        device.cpp \
                        device.hpp \
                        devregion.cpp \
                        devregion.hpp \
                        main.cpp \
                        protocol.h \
                        ring.cpp \
                        ring.hpp \
                        server.cpp \
                        server.hpp \
                        virtqueue.cpp \
                        virtqueue.hpp

rawstor_vhost_LDADD = $(top_builddir)/src/librawstor.la
