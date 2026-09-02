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
              -I$(top_srcdir)/include \
              -I$(top_srcdir)/src/3rdparty

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstor_base_ladir = $(includedir)

librawstor_base_la_HEADERS = $(top_srcdir)/include/rawstor.h

librawstor_ladir = $(includedir)/rawstor

librawstor_la_HEADERS = $(top_srcdir)/include/rawstor/list.h \
                        $(top_srcdir)/include/rawstor/location.h \
                        $(top_srcdir)/include/rawstor/object.h \
                        $(top_srcdir)/include/rawstor/protocol.h \
                        $(top_srcdir)/include/rawstor/rawio.h \
                        $(top_srcdir)/include/rawstor/rawstor.h \
                        $(top_srcdir)/include/rawstor/target.h \
                        $(top_builddir)/include/rawstor/version.h

librawstor_la_SOURCES = 3rdparty/nlohmann/json.hpp \
                        backend.cpp \
                        backend.hpp \
                        blk_backend.cpp \
                        blk_backend.hpp \
                        blkdev_meta.cpp \
                        blkdev_meta.hpp \
                        connection.cpp \
                        connection.hpp \
                        file_backend.cpp \
                        file_backend.hpp \
                        list.c \
                        location.cpp \
                        location.hpp \
                        lvm_backend.cpp \
                        lvm_backend.hpp \
                        object.cpp \
                        object.hpp \
                        ost_backend.cpp \
                        ost_backend.hpp \
                        opts.c \
                        opts.h \
                        subprocess.cpp \
                        subprocess.hpp \
                        rawstor.cpp \
                        target.cpp \
                        target.hpp \
                        telemetry.cpp \
                        telemetry.hpp \
                        zfs_backend.cpp \
                        zfs_backend.hpp

librawstor_la_LDFLAGS = -version-info $(LIBRARY_VERSION)

librawstor_la_LIBADD = $(top_builddir)/librawio/src/librawio.la \
                       $(top_builddir)/librawstd/src/librawstd.la \
                       $(LIBXXHASH_LIBS) \
                       -lstdc++


pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = rawstor.pc
