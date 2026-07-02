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
    rawstor/object.py \
    config.py \
    MANIFEST.in \
    setup.py

if ENABLE_TESTS
SOURCES += \
    tests/__init__.py \
    tests/test_basics.py
endif


sources-stamp:
	@if [ "$(srcdir)" != "$(builddir)" ]; then \
	    cp -fR --no-preserve=mode \
	        $(srcdir)/rawstor \
	        $(srcdir)/config.py \
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

$(builddir)/rawstor.egg-info/PKG-INFO: $(C_SOURCES) sources-stamp
	CFLAGS="$(CFLAGS) $(AM_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(AM_LDFLAGS)" \
	$(PYTHON) -m pip install --no-deps -e $(builddir)

install-exec-local: $(SOURCES) sources-stamp
	CFLAGS="$(CFLAGS) $(AM_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(AM_LDFLAGS)" \
	$(PYTHON) -m pip install --no-deps \
	    --prefix=$(DESTDIR)$(prefix) $(builddir)


uninstall-local:
	@echo "Uninstalling python package..."
	-rm -r $(DESTDIR)$(prefix)/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/lib/python*/dist-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/local/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/local/lib/python*/dist-packages/rawstor*

if ENABLE_TESTS
test: $(builddir)/rawstor.egg-info/PKG-INFO sources-stamp
	$(PYTHON) -m unittest discover -s $(builddir)/tests
endif

clean-local:
	$(PYTHON) $(builddir)/setup.py clean --all
	if [ "$(srcdir)" != "$(builddir)" ]; then \
	    rm -rf \
	        rawstor \
	        tests \
	        config.py \
	        MANIFEST.in \
	        setup.py \
	        sources-stamp ; \
	fi
	-rm -rf rawstor.egg-info
	-rm -rf $(builddir)/dist
	-find . -name __pycache__ -exec rm -r {} \;
	-rm -f rawstor/*.so

all-local: $(builddir)/rawstor.egg-info/PKG-INFO

EXTRA_DIST = $(SOURCES)

PHONY_TARGETS = install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
