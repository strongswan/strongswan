ipseclib_LTLIBRARIES = libchecksum.la
noinst_PROGRAMS = checksum_builder

nodist_libchecksum_la_SOURCES = checksum.c
libchecksum_la_LDFLAGS = -module -avoid-version

checksum_builder_SOURCES = checksum_builder.c
checksum_builder_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(DLLIB)

BUILT_SOURCES = checksum.c
CLEANFILES = checksum.c
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon
AM_CFLAGS = -rdynamic

libs = $(top_builddir)/src/libstrongswan/.libs/libstrongswan.so

if !MONOLITHIC
  AM_CFLAGS += -DS_PLUGINS=\""${s_plugins}\"" -DS_PATH=\""${top_builddir}/src/libstrongswan/plugins\""
endif

if USE_LIBHYDRA
  libs += $(top_builddir)/src/libhydra/.libs/libhydra.so
if !MONOLITHIC
  AM_CFLAGS += -DH_PLUGINS=\""${h_plugins}\"" -DH_PATH=\""${top_builddir}/src/libhydra/plugins\""
endif
endif

if USE_LIBTNCCS
  libs += $(top_builddir)/src/libtnccs/.libs/libtnccs.so
endif

if USE_SIMAKA
  checksum_builder_LDADD += $(top_builddir)/src/libsimaka/libsimaka.la
endif

if USE_CHARON
  libs += $(top_builddir)/src/libcharon/.libs/libcharon.so
  libs += $(top_builddir)/src/charon/.libs/charon
if !MONOLITHIC
  AM_CFLAGS += -DC_PLUGINS=\""${c_plugins}\"" -DC_PATH=\""${top_builddir}/src/libcharon/plugins\""
endif
endif

if USE_PLUTO
  libs += $(top_builddir)/src/pluto/.libs/pluto
  AM_CFLAGS += -DP_PLUGINS=\""${p_plugins}\"" -DP_PATH=\""${top_builddir}/src/pluto/plugins\""
endif

if USE_TOOLS
  libs += $(top_builddir)/src/openac/.libs/openac
  libs += $(top_builddir)/src/pki/.libs/pki
  libs += $(top_builddir)/src/scepclient/.libs/scepclient
endif

if USE_ATTR_SQL
  libs += $(top_builddir)/src/libhydra/plugins/attr_sql/.libs/pool
endif

checksum.c : checksum_builder $(libs)
		./checksum_builder $(libs) > checksum.c
