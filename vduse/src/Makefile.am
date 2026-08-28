noinst_LTLIBRARIES = libvduse.la

bin_PROGRAMS = rawstor-vduse

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/vduse/include \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


libvduse_la_SOURCES = $(top_srcdir)/vduse/include/vduse/ring.hpp \
                      $(top_srcdir)/vduse/include/vduse/request.hpp \
                      $(top_srcdir)/vduse/include/vduse/virtqueue.hpp \
                      $(top_srcdir)/include/stdheaders/linux/vduse.h \
                      $(top_srcdir)/include/stdheaders/linux/types.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_blk.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_config.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_ring.h \
                      $(top_srcdir)/include/stdheaders/linux/virtio_types.h \
                      device.cpp \
                      device.hpp \
                      iovaregion.cpp \
                      iovaregion.hpp \
                      request.cpp \
                      ring.cpp \
                      virtqueue.cpp \
                      virtqueue_worker.cpp

rawstor_vduse_SOURCES = main.cpp

rawstor_vduse_LDADD = libvduse.la \
                      $(top_builddir)/src/librawstor.la \
                      $(top_builddir)/librawstd/src/librawstd.la
