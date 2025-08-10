lib_LTLIBRARIES = librawstor.la


AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/include


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/io.h \
                        $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/uuid.h

librawstor_la_SOURCES = rawstor.c \
                        opts.c

librawstor_la_LIBADD = $(top_srcdir)/librawstorstd/src/librawstorstd.la \
                       $(top_srcdir)/librawstorio/src/librawstorio.la


if ENABLE_OST
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstor_la_SOURCES += object_ost.c
    librawstor_la_LIBADD += $(LIBXXHASH_LIBS)
else
    librawstor_la_SOURCES += object_file.c
endif


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
