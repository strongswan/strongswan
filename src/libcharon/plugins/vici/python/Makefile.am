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
