SUBDIRS = src man init testing

if USE_SCRIPTS
  SUBDIRS += scripts
endif

ACLOCAL_AMFLAGS = -I m4/config

EXTRA_DIST = Doxyfile.in LICENSE Android.mk.in Android.mk
CLEANFILES = Doxyfile
BUILT_SOURCES = Android.mk
MAINTAINERCLEANFILES = Android.mk

if USE_DEV_HEADERS
config_includedir = $(ipseclibdir)/include
nodist_config_include_HEADERS = config.h
endif

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

clean-local:
		rm -rf apidoc
