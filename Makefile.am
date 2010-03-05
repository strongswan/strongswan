SUBDIRS = src testing

if USE_SCRIPTS
  SUBDIRS += scripts
endif

ACLOCAL_AMFLAGS = -I m4/config

EXTRA_DIST = Doxyfile.in CREDITS Android.mk.in Android.mk
CLEANFILES = apidoc Doxyfile
BUILT_SOURCES = Android.mk
MAINTAINERCLEANFILES = Android.mk

Android.mk :	Android.mk.in configure.in
		sed \
		-e "s:\@PACKAGE_VERSION\@:$(PACKAGE_VERSION):" \
		$(srcdir)/$@.in > $@

Doxyfile :	Doxyfile.in
		sed \
		-e "s:\@PACKAGE_VERSION\@:$(PACKAGE_VERSION):" \
		-e "s:\@PACKAGE_NAME\@:$(PACKAGE_NAME):" \
		-e "s:\@SRC_DIR\@:$(srcdir):" \
		$(srcdir)/$@.in > $@

apidoc :	Doxyfile
		doxygen
