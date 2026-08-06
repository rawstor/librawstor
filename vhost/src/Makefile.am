noinst_LTLIBRARIES = libvhost.la

bin_PROGRAMS = rawstor-vhost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/vhost/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


libvhost_la_SOURCES = $(top_srcdir)/vhost/include/vhost/user_protocol.h \
                      $(top_srcdir)/vhost/include/vhost/ring.hpp \
                      $(top_srcdir)/vhost/include/vhost/virtqueue.hpp \
                      $(top_srcdir)/vhost/include/stdheaders/linux/vhost_types.h \
                      $(top_srcdir)/include/stdheaders/linux/types.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_blk.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_config.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_ring.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_types.h \
                      device.cpp \
                      device.hpp \
                      devregion.cpp \
                      devregion.hpp \
                      ring.cpp \
                      server.cpp \
                      server.hpp \
                      virtqueue.cpp

rawstor_vhost_SOURCES = main.cpp

rawstor_vhost_LDADD = libvhost.la \
                      $(top_builddir)/src/librawstor.la \
                      $(top_builddir)/librawstd/src/librawstd.la
