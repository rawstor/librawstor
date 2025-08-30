noinst_LTLIBRARIES = librawstorio.la


AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


librawstorio_la_SOURCES =

librawstorio_la_LIBADD =


if WITH_LIBURING
    AM_CFLAGS += $(LIBURING_CFLAGS)
    librawstorio_la_SOURCES += event_liburing.c \
                               queue_liburing.c
    librawstorio_la_LIBADD += $(LIBURING_LIBS)
else
    librawstorio_la_SOURCES += event_thread.c \
                               queue_thread.c \
                               session_seekable_thread.c \
                               session_thread.c \
                               session_unseekable_thread.c
endif
