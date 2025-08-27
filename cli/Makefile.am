bin_PROGRAMS = rawstor-cli

AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include


rawstor_cli_SOURCES = create.c \
                      delete.c \
                      main.c \
                      testio.c

rawstor_cli_LDADD = $(top_srcdir)/src/librawstor.la
