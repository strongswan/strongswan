nm_plugin_LTLIBRARIES = \
	libnm-vpn-plugin-strongswan.la \
	libnm-vpn-plugin-strongswan-editor.la

if WITH_GTK4
nm_plugin_LTLIBRARIES += \
	libnm-gtk4-vpn-plugin-strongswan-editor.la
endif

nm-strongswan-resources.h: nm-strongswan-dialog.gresource.xml
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir) \
		--generate-header --internal

nm-strongswan-resources.c: nm-strongswan-dialog.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/nm-strongswan-dialog.gresource.xml)
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ --sourcedir=$(srcdir) \
		--generate-source --internal

gtk4/nm-strongswan-resources.c: nm-strongswan-dialog.gresource.xml $(shell $(GLIB_COMPILE_RESOURCES) --sourcedir=$(srcdir) --generate-dependencies $(srcdir)/nm-strongswan-dialog.gresource.xml|sed "s,^$(srcdir)/,$(builddir)/gtk4/,")
	@mkdir -p $(builddir)/gtk4
	$(AM_V_GEN) $(GLIB_COMPILE_RESOURCES) $< --target=$@ \
		--sourcedir=$(srcdir)/gtk4 --sourcedir=$(builddir)/gtk4 \
		--generate-source --internal

gtk4/%.ui: %.ui
	@mkdir -p $(builddir)/gtk4
	gtk4-builder-tool simplify --3to4 $< | grep -v 'border-width\|can-default\|has-default' >$@

libnm_vpn_plugin_strongswan_la_SOURCES = \
	nm-strongswan-plugin.c \
	nm-strongswan-plugin.h

nodist_libnm_vpn_plugin_strongswan_editor_la_SOURCES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h

libnm_vpn_plugin_strongswan_editor_la_SOURCES = \
	nm-strongswan.c \
	nm-strongswan.h

nodist_libnm_gtk4_vpn_plugin_strongswan_editor_la_SOURCES = \
	gtk4/nm-strongswan-resources.c \
	nm-strongswan-resources.h

libnm_gtk4_vpn_plugin_strongswan_editor_la_SOURCES = \
	$(libnm_vpn_plugin_strongswan_editor_la_SOURCES)

common_CFLAGS = \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED

libnm_vpn_plugin_strongswan_la_CFLAGS = \
	$(LIBNM_CFLAGS) \
	$(common_CFLAGS)

libnm_vpn_plugin_strongswan_editor_la_CFLAGS = \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS) \
	$(common_CFLAGS)

libnm_gtk4_vpn_plugin_strongswan_editor_la_CFLAGS = \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS) \
	$(common_CFLAGS)

libnm_vpn_plugin_strongswan_la_LIBADD = \
	$(LIBNM_LIBS) \
	$(DL_LIBS)

libnm_vpn_plugin_strongswan_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNMA_LIBS) \
	$(LIBNM_LIBS)

libnm_gtk4_vpn_plugin_strongswan_editor_la_LIBADD = \
	$(GTK4_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	$(LIBNM_LIBS)

libnm_vpn_plugin_strongswan_la_LDFLAGS = \
	-avoid-version

libnm_vpn_plugin_strongswan_editor_la_LDFLAGS = \
	-avoid-version

libnm_gtk4_vpn_plugin_strongswan_editor_la_LDFLAGS = \
	-avoid-version

BUILT_SOURCES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h

if WITH_GTK4
BUILT_SOURCES += \
	gtk4/nm-strongswan-resources.c
endif

CLEANFILES = \
	nm-strongswan-resources.c \
	nm-strongswan-resources.h \
	gtk4/nm-strongswan-resources.c \
	gtk4/nm-strongswan-dialog.ui

EXTRA_DIST = \
	nm-strongswan-dialog.ui \
	nm-strongswan-dialog.gresource.xml
