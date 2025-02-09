if ENABLE_TESTS
    MAYBE_TESTS = tests
endif

SUBDIRS = src \
          cli \
          vu \
          $(MAYBE_TESTS)


ACLOCAL_AMFLAGS = -I m4


README: README.md


if ENABLE_TESTS
test: all
	make -C tests test

.PHONY: test
endif
