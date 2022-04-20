AUTOMAKE_OPTIONS = foreign

SUBDIRS = properties auth-dialog po

nmvpnservice_DATA = nm-strongswan-service.name

@INTLTOOL_DESKTOP_RULE@

metainfodir = $(datadir)/metainfo
metainfo_DATA = $(metainfo_in_files:.xml.in=.xml)
metainfo_in_files = NetworkManager-strongswan.metainfo.xml.in
@INTLTOOL_XML_RULE@

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	$(AM_V_GEN) \
	sed -e 's|[@]NM_LIBEXECDIR[@]|$(nm_libexecdir)|' \
	    -e 's|[@]NM_PLUGINDIR[@]|$(nm_plugindir)|g' \
	    -e 's|[@]NM_PLUGINDIR_ABS[@]/|$(nm_plugindir_abs)|g' \
	    -e 's|[@]CHARON[@]|$(charon)|' $< >$@

EXTRA_DIST = \
    nm-strongswan-service.name.in  \
    $(metainfo_in_files)  \
    intltool-extract.in  \
    intltool-merge.in    \
    intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(metainfo_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4
