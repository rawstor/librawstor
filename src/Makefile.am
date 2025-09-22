lib_LTLIBRARIES = librawstor.la


GENERIC_FLAGS = -Wall -Wextra -Werror \
                -I$(top_srcdir)/librawstorstd/include \
                -I$(top_srcdir)/librawstorio/include \
                -I$(top_srcdir)/include

AM_CFLAGS = -std=gnu99 $(GENERIC_FLAGS)

AM_CXXFLAGS = -std=c++20 $(GENERIC_FLAGS)


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/io_event.h \
                        $(top_srcdir)/include/rawstor/io_queue.h \
                        $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/uuid.h

librawstor_la_SOURCES = connection.cpp \
                        object.cpp \
                        opts.c \
                        rawstor.cpp

librawstor_la_LIBADD = $(top_srcdir)/librawstorstd/src/librawstorstd.la \
                       $(top_srcdir)/librawstorio/src/librawstorio.la \
                       -lstdc++


if ENABLE_OST
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    librawstor_la_SOURCES += socket_ost.cpp
    librawstor_la_LIBADD += $(LIBXXHASH_LIBS)
else
    librawstor_la_SOURCES += socket_file.cpp
endif


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
