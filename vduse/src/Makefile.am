noinst_LTLIBRARIES = librawstor-vduse.la

bin_PROGRAMS = rawstor-vduse

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/vduse/include \
              -I$(top_srcdir)/vduse/3rdparty/qemu/libvduse \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstor_vduse_la_SOURCES = $(top_srcdir)/vduse/include/vduse/request.hpp \
                              device.cpp \
                              device.hpp \
                              request.cpp \
                              server.cpp \
                              server.hpp

rawstor_vduse_SOURCES = main.cpp

rawstor_vduse_LDADD = librawstor-vduse.la \
                      $(top_builddir)/vduse/3rdparty/qemu/libvduse/libvduse.la \
                      $(top_builddir)/src/librawstor.la \
                      $(top_builddir)/librawstd/src/librawstd.la
