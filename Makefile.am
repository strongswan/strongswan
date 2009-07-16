SUBDIRS = src testing

if USE_SCRIPTS
  SUBDIRS += scripts
endif

EXTRA_DIST = Doxyfile.in CREDITS
CLEANFILES = apidoc Doxyfile

Doxyfile :	Doxyfile.in
		sed \
		-e "s:\@PACKAGE_VERSION\@:$(PACKAGE_VERSION):" \
		-e "s:\@PACKAGE_NAME\@:$(PACKAGE_NAME):" \
		$(srcdir)/$@.in > $@

apidoc :	Doxyfile
		doxygen
