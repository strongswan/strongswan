statuslib_LTLIBRARIES = libstrongswan-status.la
libstrongswan_status_la_SOURCES = \
	strongswan-status.c strongswan-status.h \
	strongswan-connection.c strongswan-connection.h \
	strongswan-connections.c strongswan-connections.h

libstrongswan_status_la_LIBADD = $(HILDON_LIBS) $(DBUS_LIBS) $(OSSO_LIBS)
libstrongswan_status_la_CFLAGS = -DUSE_DYNAMIC_TYPES \
	$(HILDON_CFLAGS) $(DBUS_CFLAGS) $(OSSO_CFLAGS)
libstrongswan_status_la_LDFLAGS = -module -avoid-version

pluginlib_LTLIBRARIES = libstrongswan-settings.la
libstrongswan_settings_la_SOURCES = \
	strongswan-settings.c \
	strongswan-connection.c strongswan-connection.h \
	strongswan-connections.c strongswan-connections.h

libstrongswan_settings_la_LIBADD = $(HILDON_LIBS)
libstrongswan_settings_la_CFLAGS = $(HILDON_CFLAGS)
libstrongswan_settings_la_LDFLAGS = -module -avoid-version

