AUTOMAKE_OPTIONS = foreign

SUBDIRS = properties auth-dialog po

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-strongswan-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-strongswan-service.name

@INTLTOOL_DESKTOP_RULE@

appdatadir = $(datadir)/appdata
appdata_DATA = $(appdata_in_files:.xml.in=.xml)
appdata_in_files = NetworkManager-strongswan.appdata.xml.in
@INTLTOOL_XML_RULE@

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	$(AM_V_GEN) \
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|' \
	    -e 's|[@]CHARON[@]|$(charon)|' $< >$@

EXTRA_DIST = nm-strongswan-service.name.in \
    $(dbusservice_DATA)  \
    $(appdata_in_files)  \
    $(appdata_DATA)      \
    intltool-extract.in  \
    intltool-merge.in    \
    intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(appdata_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
