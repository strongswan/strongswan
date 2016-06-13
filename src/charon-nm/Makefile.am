ipsec_PROGRAMS = charon-nm

charon_nm_SOURCES = \
	charon-nm.c \
	nm/nm_backend.c nm/nm_backend.h \
	nm/nm_creds.c nm/nm_creds.h \
	nm/nm_handler.c nm/nm_handler.h \
	nm/nm_service.c nm/nm_service.h

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DNM_CA_DIR=\"${nm_ca_dir}\" \
	-DPLUGINS=\""${nm_plugins}\""

AM_CFLAGS = \
	${nm_CFLAGS}

charon_nm_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lm $(PTHREADLIB) $(DLLIB) ${nm_LIBS}

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-strongswan-service.conf

nmvpnservicedir = $(prefix)/lib/NetworkManager/VPN
nmvpnservice_DATA = nm-strongswan-service.name

# Install a file with full path to plugins for an old gnome-shell
# https://bugzilla.gnome.org/show_bug.cgi?id=693590
install-data-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/NetworkManager/VPN
	sed -e "1s|^|# This file is obsoleted by a file in $(NM_VPN_SERVICE_DIR)\n\n|" \
	    -e 's|[@]NM_LIBEXECDIR[@]|$(nm_libexecdir)|g' \
	    -e 's|[@]NM_PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    -e 's|[@]IPSECDIR[@]|${ipsecdir}|' \
	    <$(srcdir)/nm-strongswan-service.name.in \
	    >$(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-strongswan-service.name

uninstall-hook:
	 rm -f $(DESTDIR)$(sysconfdir)/NetworkManager/VPN/nm-strongswan-service.name

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	$(AM_V_GEN) \
	sed -e 's|[@]NM_LIBEXECDIR[@]|$(nm_libexecdir)|' \
	    -e 's|[@]NM_PLUGINDIR[@]/|$(nm_plugindir)|g' \
	    -e 's|[@]IPSECDIR[@]|${ipsecdir}|' $< >$@

EXTRA_DIST = nm-strongswan-service.name.in
