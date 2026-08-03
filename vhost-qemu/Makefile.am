SUBDIRS = 3rdparty

noinst_PROGRAMS = rawstor-vhost-qemu

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include \
              -I$(srcdir)/3rdparty/qemu/libvhost-user

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_vhost_qemu_SOURCES = device.cpp \
                             device.hpp \
                             main.cpp \
                             server.cpp \
                             server.hpp

rawstor_vhost_qemu_LDADD = $(top_builddir)/src/librawstor.la \
                           $(top_builddir)/vhost-qemu/3rdparty/qemu/libvhost-user/libvhost-user.la
