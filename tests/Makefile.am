AM_CFLAGS = -std=gnu99 -Wall -Wextra -Werror \
            -I$(top_srcdir)/include \
            -I$(top_srcdir)/src


test: all
	@for test in $(noinst_PROGRAMS); do \
	    echo $${test}; \
	    ./$${test} || exit 1; \
	done
	@echo Success!!!


.PHONY: test
