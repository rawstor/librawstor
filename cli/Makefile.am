bin_PROGRAMS = rawstor-cli

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


rawstor_cli_SOURCES = create.c \
                      main.c \
                      remove.c \
                      show.c \
                      testio.c

rawstor_cli_LDADD = $(top_srcdir)/src/librawstor.la -lstdc++
