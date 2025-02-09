bin_PROGRAMS = rawstor-vu

AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include


rawstor_vu_SOURCES = main.c \
                     server.c

rawstor_vu_LDADD = $(top_srcdir)/src/librawstor.la
