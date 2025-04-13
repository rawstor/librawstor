lib_LTLIBRARIES = librawstor.la


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include


librawstor_ladir = $(includedir)

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_la_SOURCES = hash.c \
                        iovec_routines.c \
                        mempool.c \
                        pool.c \
                        rawstor.c \
                        uuid.c

librawstor_la_LIBADD =


if ENABLE_OST
    librawstor_la_SOURCES += object_ost.c
    librawstor_la_LIBADD += $(LIBXXHASH_LIBS)
else
    librawstor_la_SOURCES += object_file.c
endif

if WITH_LIBURING
    AM_CFLAGS += $(LIBURING_CFLAGS)
    librawstor_la_SOURCES += io_liburing.c
    librawstor_la_LIBADD += $(LIBURING_LIBS)
else
    librawstor_la_SOURCES += io_poll.c
endif


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
