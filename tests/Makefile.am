noinst_PROGRAMS = test_dummy

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src

AM_LDFLAGS = $(ASAN_LDFLAGS)


test_dummy_SOURCES = $(top_srcdir)/tests/unittest.h \
                     test_dummy.c
test_dummy_LDADD = $(top_builddir)/src/librawstor.la


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
