SUBDIRS = .

if ENABLE_TESTS
SUBDIRS += tests
endif

noinst_LTLIBRARIES = libvhostcore.la

bin_PROGRAMS = rawstor-vhost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


libvhostcore_la_SOURCES = stdheaders/linux/types.h \
                          stdheaders/linux/vhost_types.h \
                          stdheaders/linux/virtio_blk.h \
                          stdheaders/linux/virtio_config.h \
                          stdheaders/linux/virtio_ring.h \
                          stdheaders/linux/virtio_types.h \
                          device.cpp \
                          device.hpp \
                          devregion.cpp \
                          devregion.hpp \
                          protocol.h \
                          ring.cpp \
                          ring.hpp \
                          server.cpp \
                          server.hpp \
                          virtqueue.cpp \
                          virtqueue.hpp

rawstor_vhost_SOURCES = main.cpp

rawstor_vhost_LDADD = libvhostcore.la \
                      $(top_builddir)/src/librawstor.la


if ENABLE_TESTS
test: all
	make -C tests test

.PHONY: test
endif
