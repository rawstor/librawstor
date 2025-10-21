bin_PROGRAMS = rawstor-vhost

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_vhost_SOURCES = main.cpp \
                        protocol.h \
                        server.c \
                        server.h

rawstor_vhost_LDADD = $(top_builddir)/src/librawstor.la
