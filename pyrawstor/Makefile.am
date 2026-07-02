if ENABLE_TESTS
ENABLE_TESTS = yes
else
ENABLE_TESTS = no
endif

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
	        $(builddir); \
	    if [ "x$(ENABLE_TESTS)" = "xyes" ]; then \
	        cp -fR --no-preserve=mode \
	            $(srcdir)/tests \
	            $(builddir); \
	    fi \
	fi
	touch $@

rawstor.egg-info/PKG-INFO: $(C_SOURCES)
	$(PYTHON) setup.py develop

develop: rawstor.egg-info/PKG-INFO

$(builddir)/build-stamp: $(SOURCES) sources-stamp
	$(PYTHON) setup.py build
	touch $@

build-rawstor: $(builddir)/build-stamp

install-exec-local: build-rawstor
	$(PYTHON) setup.py install \
	    --prefix=$(DESTDIR)$(prefix)

uninstall-local:
	@echo "Uninstalling python package..."
	-rm -r $(DESTDIR)$(prefix)/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/lib/python*/dist-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/local/lib/python*/site-packages/rawstor*
	-rm -r $(DESTDIR)$(prefix)/local/lib/python*/dist-packages/rawstor*

if ENABLE_TESTS
test: rawstor.egg-info/PKG-INFO sources-stamp
	$(PYTHON) -m unittest discover -s tests
endif

clean-local:
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
	-rm -rf $(builddir)/build $(builddir)/build-stamp
	-rm -rf $(builddir)/dist
	-find . -name __pycache__ -exec rm -r {} \;
	-rm -f rawstor/*.so

all-local: build-rawstor

EXTRA_DIST = $(SOURCES)

PHONY_TARGETS = install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
