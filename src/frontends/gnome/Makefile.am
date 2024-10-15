AUTOMAKE_OPTIONS = foreign

SUBDIRS = properties auth-dialog po

nmvpnservice_DATA = nm-strongswan-service.name

metainfodir = $(datadir)/metainfo
metainfo_DATA = $(metainfo_in_files:.xml.in=.xml)
metainfo_in_files = NetworkManager-strongswan.metainfo.xml.in

%.xml: %.xml.in
	$(AM_V_GEN) $(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

nm-strongswan-service.name: $(srcdir)/nm-strongswan-service.name.in
	$(AM_V_GEN) \
	sed -e 's|[@]NM_LIBEXECDIR[@]|$(nm_libexecdir)|' \
	    -e 's|[@]NM_PLUGINDIR[@]|$(nm_plugindir)|g' \
	    -e 's|[@]NM_PLUGINDIR_ABS[@]/|$(nm_plugindir_abs)|g' \
	    -e 's|[@]CHARON[@]|$(charon)|' $< >$@

EXTRA_DIST = \
    nm-strongswan-service.name.in  \
    $(metainfo_in_files)

CLEANFILES = $(nmvpnservice_DATA) $(metainfo_DATA) *~

ACLOCAL_AMFLAGS = -I m4
