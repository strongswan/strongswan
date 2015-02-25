EXTRA_DIST = LICENSE MANIFEST.in \
	setup.py.in \
	vici/__init__.py \
	vici/exception.py \
	vici/protocol.py \
	vici/session.py

setup.py: $(srcdir)/setup.py.in
	$(AM_V_GEN) sed \
	-e "s:@EGG_VERSION@:$(PACKAGE_VERSION):" \
	$(srcdir)/setup.py.in > $@

all-local: dist/vici-$(PACKAGE_VERSION)-py$(PYTHON_VERSION).egg

dist/vici-$(PACKAGE_VERSION)-py$(PYTHON_VERSION).egg: $(EXTRA_DIST) setup.py
	(cd $(srcdir); $(PYTHON) setup.py bdist_egg \
		-b $(shell readlink -f $(builddir))/build \
		-d $(shell readlink -f $(builddir))/dist)

clean-local: setup.py
	$(PYTHON) setup.py clean -a
	rm -rf vici.egg-info dist setup.py

install-exec-local: dist/vici-$(PACKAGE_VERSION)-py$(PYTHON_VERSION).egg
	$(EASY_INSTALL) $(PYTHONEGGINSTALLDIR) \
		dist/vici-$(PACKAGE_VERSION)-py$(PYTHON_VERSION).egg
