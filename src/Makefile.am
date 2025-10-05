lib_LTLIBRARIES = librawstor.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/io_event.h \
                        $(top_srcdir)/include/rawstor/io_queue.h \
                        $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/uuid.h

librawstor_la_SOURCES = connection.cpp \
                        driver.cpp \
                        file_driver.cpp \
                        object.cpp \
                        ost_driver.cpp \
                        opts.c \
                        rawstor.cpp

librawstor_la_LIBADD = $(top_srcdir)/librawstorstd/src/librawstorstd.la \
                       $(top_srcdir)/librawstorio/src/librawstorio.la \
                       -lstdc++


if ENABLE_OST
    AM_CFLAGS += $(LIBXXHASH_CFLAGS)
    AM_CXXFLAGS += $(LIBXXHASH_CFLAGS)
    librawstor_la_LIBADD += $(LIBXXHASH_LIBS)
endif


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
