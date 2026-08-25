bin_PROGRAMS = rawstor

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstd/include \
            -I$(top_srcdir)/librawio/include \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_SOURCES = create.c \
                  create.h \
                  info.c \
                  info.h \
                  list.c \
                  list.h \
                  main.c \
                  rawio_sync.c \
                  rawio_sync.h \
                  remove.c \
                  remove.h \
                  show.c \
                  show.h \
                  testio.c \
                  testio.h

rawstor_LDADD = $(top_builddir)/src/librawstor.la \
                $(top_builddir)/librawstd/src/librawstd.la \
                -lstdc++
