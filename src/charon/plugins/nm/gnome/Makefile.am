AUTOMAKE_OPTIONS = foreign

SUBDIRS = properties po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-strongswan-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-strongswan-service.name

@INTLTOOL_DESKTOP_RULE@

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = nm-strongswan-service.name.in \
             $(dbusservice_DATA)  \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update
