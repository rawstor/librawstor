lib_LTLIBRARIES = librawstor.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(LIBXXHASH_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstd/include \
            -I$(top_srcdir)/librawio/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(LIBXXHASH_CFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstd/include \
              -I$(top_srcdir)/librawio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/ost_protocol.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/version.h

librawstor_la_SOURCES = connection.cpp \
                        connection.hpp \
                        file_session.cpp \
                        file_session.hpp \
                        object.cpp \
                        object.hpp \
                        ost_session.cpp \
                        ost_session.hpp \
                        opts.c \
                        opts.h \
                        session.cpp \
                        session.hpp \
                        rawstor.cpp \
                        rawstor_internals.hpp

librawstor_la_LDFLAGS = -version-info $(LIBRARY_VERSION)

librawstor_la_LIBADD = $(top_builddir)/librawio/src/librawio.la \
                       $(top_builddir)/librawstd/src/librawstd.la \
                       $(LIBXXHASH_LIBS) \
                       -lstdc++


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
