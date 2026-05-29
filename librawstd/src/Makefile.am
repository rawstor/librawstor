noinst_LTLIBRARIES = librawstd.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstd/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstd_la_SOURCES = $(top_srcdir)/librawstd/include/rawstd/endian.h \
                       $(top_srcdir)/librawstd/include/rawstd/gcc.h \
                       $(top_srcdir)/librawstd/include/rawstd/gpp.hpp \
                       $(top_srcdir)/librawstd/include/rawstd/hash.h \
                       $(top_srcdir)/librawstd/include/rawstd/iovec.h \
                       $(top_srcdir)/librawstd/include/rawstd/list.h \
                       $(top_srcdir)/librawstd/include/rawstd/logging.h \
                       $(top_srcdir)/librawstd/include/rawstd/logging.hpp \
                       $(top_srcdir)/librawstd/include/rawstd/logging_config.h \
                       $(top_srcdir)/librawstd/include/rawstd/mempool.h \
                       $(top_srcdir)/librawstd/include/rawstd/mempool.hpp \
                       $(top_srcdir)/librawstd/include/rawstd/ringbuf.hpp \
                       $(top_srcdir)/librawstd/include/rawstd/socket.h \
                       $(top_srcdir)/librawstd/include/rawstd/threading.h \
                       $(top_srcdir)/librawstd/include/rawstd/uri.hpp \
                       $(top_srcdir)/librawstd/include/rawstd/uuid.h \
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

librawstd_la_LIBADD =


if WITH_LIBXXHASH
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstd_la_LIBADD += $(LIBXXHASH_LIBS)
endif
