build-rawstor:
	if [ "$(srcdir)" != "." ]; then \
	  cp -fR $(srcdir)/rawstor \
	         $(srcdir)/tests \
	         $(srcdir)/MANIFEST.in \
	         $(srcdir)/setup.py .; \
	fi
	cd $(srcdir) && $(PYTHON) -m build

install-rawstor:
	$(PYTHON) -m pip install $(srcdir)

if ENABLE_TESTS
test:
	cd $(srcdir) && $(PYTHON) -m unittest
	if [ "$(srcdir)" != "." ]; then \
	  rm -rf rawstor \
	         tests \
	         MANIFEST.in \
	         setup.py; \
	fi
endif

clean-local:
	-rm -rf $(srcdir)/build $(srcdir)/dist $(srcdir)/*.egg-info $(srcdir)/__pycache__

all-local: build-rawstor

.PHONY: install-rawstor

if ENABLE_TESTS
.PHONY: test
endif
