noinst_LTLIBRARIES = librawstorstd.la


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include


librawstorstd_la_SOURCES = hash.c \
                           iovec_routines.c \
                           list.c \
                           mempool.c \
                           ringbuf.c \
                           socket_routines.c \
                           threading.c \
                           uuid.c

librawstorstd_la_LIBADD =


if WITH_LIBXXHASH
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstorstd_la_LIBADD += $(LIBXXHASH_LIBS)
endif
