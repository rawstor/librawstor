SUBDIRS = 3rdparty \
          src

if ENABLE_TESTS
    SUBDIRS += tests
endif


if ENABLE_TESTS
test: all
	make -C tests test

.PHONY: test
endif
