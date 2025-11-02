noinst_LTLIBRARIES = librawstorstd.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstorstd_la_SOURCES = $(top_srcdir)/librawstorstd/include/rawstorstd/gcc.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/gpp.hpp \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/hash.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/iovec.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/list.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/logging.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/logging_config.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/mempool.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/mempool.hpp \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/ringbuf.hpp \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/socket.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/threading.h \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/uri.hpp \
                           $(top_srcdir)/librawstorstd/include/rawstorstd/uuid.h \
                           hash.c \
                           iovec.c \
                           list.c \
                           logging.cpp \
                           mempool.c \
                           socket.c \
                           threading.c \
                           uri.cpp \
                           uuid.c \
                           uuid_internals.h

librawstorstd_la_LIBADD =


if WITH_LIBXXHASH
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstorstd_la_LIBADD += $(LIBXXHASH_LIBS)
endif
