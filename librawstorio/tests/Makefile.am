AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/librawstorio/src \
            -I$(top_srcdir)/librawstorio/include \
            -I$(top_srcdir)/librawstorstd/include \
            -I$(top_srcdir)/tests \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
