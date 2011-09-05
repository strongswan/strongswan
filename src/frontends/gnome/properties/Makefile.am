plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-strongswan-properties.la

libnm_strongswan_properties_la_SOURCES = \
	nm-strongswan.c \
	nm-strongswan.h

uidir = $(datadir)/gnome-vpn-properties/strongswan
ui_DATA = nm-strongswan-dialog.ui

libnm_strongswan_properties_la_CFLAGS = \
	$(GTK_CFLAGS) \
	$(NM_UTILS_CFLAGS) \
	-DUIDIR=\""$(uidir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DVERSION=\"$(VERSION)\"

libnm_strongswan_properties_la_LIBADD =      \
	$(GTK_LIBS) \
	$(NM_UTILS_LIBS)

libnm_strongswan_properties_la_LDFLAGS =     \
	-avoid-version

EXTRA_DIST = $(ui_DATA)
