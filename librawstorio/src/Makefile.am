noinst_LTLIBRARIES = librawstorio.la


GENERIC_FLAGS = -Wall -Wextra -Werror \
                -I$(top_srcdir)/librawstorio/include \
                -I$(top_srcdir)/librawstorstd/include \
                -I$(top_srcdir)/include

AM_CFLAGS = -std=gnu99 $(GENERIC_FLAGS)

AM_CXXFLAGS = -std=c++20 $(GENERIC_FLAGS)


librawstorio_la_SOURCES = queue.cpp

librawstorio_la_LIBADD =


if WITH_LIBURING
    AM_CFLAGS += $(LIBURING_CFLAGS)
    librawstorio_la_SOURCES += event_liburing.c \
                               queue_liburing.c
    librawstorio_la_LIBADD += $(LIBURING_LIBS)
else
    librawstorio_la_SOURCES += event_poll.c \
                               queue_poll.c \
                               session_poll.c
endif
