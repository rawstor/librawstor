build-rawstor:
	cd $(srcdir) && $(PYTHON) -m build

install-rawstor:
	$(PYTHON) -m pip install $(srcdir)

if ENABLE_TESTS
test:
	cd $(srcdir) && $(PYTHON) -m unittest
endif

clean-local:
	-rm -rf $(srcdir)/build $(srcdir)/dist $(srcdir)/*.egg-info $(srcdir)/__pycache__

all-local: build-rawstor

.PHONY: install-rawstor

if ENABLE_TESTS
.PHONY: test
endif
