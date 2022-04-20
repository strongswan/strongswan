nm_plugin_LTLIBRARIES = libnm-vpn-plugin-strongswan.la

libnm_vpn_plugin_strongswan_la_SOURCES = \
	nm-strongswan.c \
	nm-strongswan.h

uidir = $(datadir)/gnome-vpn-properties/strongswan
ui_DATA = nm-strongswan-dialog.ui

common_CFLAGS = \
	$(GTK_CFLAGS) \
	-DUIDIR=\""$(uidir)"\" \
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

EXTRA_DIST = $(ui_DATA)
