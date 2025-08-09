SUBDIRS = rawstorstd\
          src \
          cli \
          vu

if ENABLE_TESTS
    SUBDIRS += tests
endif


ACLOCAL_AMFLAGS = -I m4


README: README.md


if ENABLE_TESTS
test: all
	make -C tests test

.PHONY: test
endif
