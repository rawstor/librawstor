SUBDIRS = 3rdparty

noinst_PROGRAMS = rawstor-vhost

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include \
              -I$(srcdir)/3rdparty/qemu/libvhost-user

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_vhost_SOURCES = device.cpp \
                        device.hpp \
                        main.cpp \
                        server.cpp \
                        server.hpp

rawstor_vhost_LDADD = $(top_builddir)/src/librawstor.la \
                      $(top_builddir)/vhost/3rdparty/qemu/libvhost-user/libvhost-user.la
