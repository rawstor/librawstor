noinst_LTLIBRARIES = librawstorstd.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstorstd_la_SOURCES = hash.c \
                           iovec.c \
                           list.c \
                           logging.c \
                           mempool.c \
                           ringbuf.c \
                           socket.c \
                           socket_address.cpp \
                           threading.c \
                           uuid.c

librawstorstd_la_LIBADD =


if WITH_LIBXXHASH
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstorstd_la_LIBADD += $(LIBXXHASH_LIBS)
endif
