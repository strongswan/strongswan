nm_plugin_LTLIBRARIES = libnm-vpn-plugin-strongswan.la

nm-strongswan-resources.h: nm-strongswan-dialog.gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir) \
		--generate-header --internal

nm-strongswan-resources.c: nm-strongswan-dialog.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/nm-strongswan-dialog.gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir) \
		--generate-source --internal

nodist_libnm_vpn_plugin_strongswan_la_SOURCES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h

libnm_vpn_plugin_strongswan_la_SOURCES = \
	nm-strongswan.c \
	nm-strongswan.h

common_CFLAGS = \
	$(GTK_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED

libnm_vpn_plugin_strongswan_la_CFLAGS = \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(common_CFLAGS)

libnm_vpn_plugin_strongswan_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBNM_LIBS)

libnm_vpn_plugin_strongswan_la_LDFLAGS = \
	-avoid-version

BUILT_SOURCES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h

CLEANFILES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h

EXTRA_DIST = \
	nm-strongswan-dialog.ui \
	nm-strongswan-dialog.gresource.xml
