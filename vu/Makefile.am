noinst_PROGRAMS = rawstor-vu

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_vu_SOURCES = main.c \
                     protocol.h \
                     server.c \
                     server.h

rawstor_vu_LDADD = $(top_builddir)/src/librawstor.la -lstdc++
