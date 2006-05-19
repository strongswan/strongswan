SUBDIRS = src
EXTRA_DIST = Doxyfile.in
CLEANFILES = apidoc Doxyfile

Doxyfile :	Doxyfile.in
		sed \
		-e "s:\@PACKAGE_VERSION\@:$(PACKAGE_VERSION):" \
		-e "s:\@PACKAGE_NAME\@:$(PACKAGE_NAME):" \
		$< > $@

apidoc :	Doxyfile
		doxygen
