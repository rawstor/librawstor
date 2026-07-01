if ENABLE_TESTS
ENABLE_TESTS = yes
else
ENABLE_TESTS = no
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

$(builddir)/build-stamp: sources-stamp setup.py
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
test: sources-stamp
	$(PYTHON) -m unittest discover -s tests
endif

clean-local:
	if [ "$(srcdir)" != "$(builddir)" ]; then \
	  rm -rf \
	    rawstor \
	    rawstor.egg-info \
	    tests \
	    config.py \
	    MANIFEST.in \
	    setup.py \
	    sources-stamp ; \
	fi
	-rm -rf $(builddir)/build $(builddir)/build-stamp
	-rm -rf $(builddir)/dist
	-rm *.so

all-local: build-rawstor

EXTRA_DIST = \
    rawstor/module.c \
    rawstor/rawstor.c \
    rawstor/rawstor.h \
    config.py \
    MANIFEST.in \
    setup.py

if ENABLE_TESTS
EXTRA_DIST += \
    tests/__init__.py \
    tests/test_basics.py
endif

PHONY_TARGETS = install-rawstor

if ENABLE_TESTS
PHONY_TARGETS += test
endif

.PHONY: $(PHONY_TARGETS)
