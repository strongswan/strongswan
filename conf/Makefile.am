EXTRA_DIST = strongswan.conf

install-exec-local :
		test -e "$(DESTDIR)${sysconfdir}" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)"
		test -e "$(DESTDIR)$(sysconfdir)/strongswan.conf" || $(INSTALL) -m 640 $(srcdir)/strongswan.conf $(DESTDIR)$(sysconfdir)/strongswan.conf || true
