bin_PROGRAMS = rawstor-cli

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_cli_SOURCES = create.c \
					  create.h \
                      main.c \
                      remove.c \
                      remove.h \
                      show.c \
                      show.h \
                      testio.c \
                      testio.h

rawstor_cli_LDADD = $(top_builddir)/src/librawstor.la -lstdc++
