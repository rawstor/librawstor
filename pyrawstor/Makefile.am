build-rawstor:
	cd $(srcdir) && $(PYTHON) -m build

install-rawstor:
	$(PYTHON) -m pip install $(srcdir)

test:
	cd $(srcdir) && $(PYTHON) -m pytest

clean-local:
	-rm -rf $(srcdir)/build $(srcdir)/dist $(srcdir)/*.egg-info $(srcdir)/__pycache__

all-local: build-rawstor

.PHONY: install-rawstor test
