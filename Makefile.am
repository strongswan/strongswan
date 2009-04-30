SUBDIRS = src testing scripts
EXTRA_DIST = Doxyfile.in CREDITS
CLEANFILES = apidoc Doxyfile

Doxyfile :	Doxyfile.in
		sed \
		-e "s:\@PACKAGE_VERSION\@:$(PACKAGE_VERSION):" \
		-e "s:\@PACKAGE_NAME\@:$(PACKAGE_NAME):" \
		$(srcdir)/$@.in > $@

apidoc :	Doxyfile
		doxygen

dist-hook :
		rm -rf `find $(distdir)/testing -name .svn`
