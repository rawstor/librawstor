lib_LTLIBRARIES = librawstor.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(LIBXXHASH_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/include

AM_CXXFLAGS = $(GENERIC_CXXFLAGS) \
              $(LIBXXHASH_CFLAGS) \
              $(ASAN_CFLAGS) \
              -I$(top_srcdir)/librawstorstd/include \
              -I$(top_srcdir)/librawstorio/include \
              -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/uuid.h

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
                        ost_protocol.h \
                        session.cpp \
                        session.hpp \
                        rawstor.cpp \
                        rawstor_internals.hpp \
                        task.hpp

librawstor_la_LDFLAGS = -version-info $(LIBRARY_VERSION)

librawstor_la_LIBADD = $(top_builddir)/librawstorstd/src/librawstorstd.la \
                       $(top_builddir)/librawstorio/src/librawstorio.la \
                       $(LIBXXHASH_LIBS) \
                       -lstdc++


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
