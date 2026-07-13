if ENABLE_TESTS
ENABLE_TESTS = yes
else
ENABLE_TESTS = no
endif

AM_CFLAGS = $(GENERIC_CFLAGS) \
            $(LIBXXHASH_CFLAGS) \
            $(ASAN_CFLAGS) \
            -I$(top_srcdir)/include

AM_LDFLAGS = $(ASAN_LDFLAGS)

C_SOURCES = \
    rawstor/librawstor/module.c \
    rawstor/librawstor/object_bindings.c \
    rawstor/librawstor/object_bindings.h

SOURCES = \
    $(C_SOURCES) \
    rawstor/__init__.py \
    rawstor/location.py \
    rawstor/target.py \
    config.py \
    MANIFEST.in \
    setup.py

if ENABLE_TESTS
SOURCES += \
    tests/__init__.py \
    tests/test_location.py \
    tests/test_target.py
endif


$(builddir)/sources-stamp:
	@if [ "$(srcdir)" != "$(builddir)" ]; then \
	    cp -fR --no-preserve=mode \
	        $(srcdir)/rawstor \
	        $(srcdir)/MANIFEST.in \
	        $(srcdir)/setup.py \
	        .; \
	    if [ "x$(ENABLE_TESTS)" = "xyes" ]; then \
	        cp -fR --no-preserve=mode \
	            $(srcdir)/tests \
	            .; \
	    fi \
	fi
	touch $@

$(builddir)/build-stamp: $(C_SOURCES) $(builddir)/sources-stamp setup.py $(top_srcdir)/src/.libs/librawstor.la
	CFLAGS="$(CFLAGS) $(AM_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(AM_LDFLAGS)" \
	$(PYTHON) -m pip install \
	    --no-deps \
	    --no-build-isolation \
	    -e $(builddir)
	touch $@

if WITH_PYTHON3
install-exec-local: $(SOURCES) sources-stamp
	CFLAGS="$(CFLAGS) $(AM_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(AM_LDFLAGS)" \
	$(PYTHON) -m pip install \
	    --no-deps \
	    --root=$(DESTDIR) \
	    --prefix=$(prefix) \
	    $(builddir)


uninstall-local:
	@echo "Uninstalling python package..."
	-rm -r $(DESTDIR)/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)/lib/python*/dist-packages/rawstor*
	-rm -r $(DESTDIR)/local/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)/local/lib/python*/dist-packages/rawstor*

if ENABLE_TESTS
test: $(builddir)/build-stamp
	LD_LIBRARY_PATH=$(top_srcdir)/src/.libs:$(LD_LIBRARY_PATH) \
	DYLD_LIBRARY_PATH=$(top_srcdir)/src/.libs:$(DYLD_LIBRARY_PATH) \
	$(PYTHON) -m unittest discover -s $(builddir)/tests
endif

clean-local:
	$(PYTHON) $(builddir)/setup.py clean --all
	@if [ "$(srcdir)" != "$(builddir)" ]; then \
	    rm -rf \
	        rawstor \
	        tests \
	        MANIFEST.in \
	        setup.py ; \
	fi
	-find . -name __pycache__ -exec rm -r {} \;
	-rm -rf \
	    $(builddir)/build-stamp \
	    $(builddir)/dist \
	    $(builddir)/sources-stamp
	-rm -rf rawstor.egg-info
	-rm -f rawstor/*.so

all-local: $(builddir)/build-stamp
endif

EXTRA_DIST = $(SOURCES)

PHONY_TARGETS =

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
