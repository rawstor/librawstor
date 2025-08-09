if ENABLE_TESTS
    MAYBE_TESTS = tests
endif

SUBDIRS = src \
          $(MAYBE_TESTS)


if ENABLE_TESTS
test: all
	make -C tests test

.PHONY: test
endif
