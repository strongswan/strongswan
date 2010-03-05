SUBDIRS = . include

if USE_LIBSTRONGSWAN
  SUBDIRS += libstrongswan
endif

if USE_SIMAKA
  SUBDIRS += libsimaka
endif

if USE_FILE_CONFIG
  SUBDIRS += libfreeswan starter ipsec _copyright
endif

if USE_PLUTO
  SUBDIRS += pluto whack
endif

if USE_CHARON
  SUBDIRS += charon
endif

if USE_STROKE
  SUBDIRS += stroke
endif

if USE_UPDOWN
  SUBDIRS += _updown _updown_espmark
endif

if USE_TOOLS
  SUBDIRS += libfreeswan openac scepclient pki
endif

if USE_DUMM
  SUBDIRS += dumm
endif

if USE_FAST
  SUBDIRS += libfast
endif

if USE_MANAGER
  SUBDIRS += manager
endif

if USE_MEDSRV
  SUBDIRS += medsrv
endif

if USE_INTEGRITY_TEST
  SUBDIRS += checksum
endif

EXTRA_DIST = strongswan.conf

install-exec-local :
		test -e "$(DESTDIR)${sysconfdir}" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)"
		test -e "$(DESTDIR)$(sysconfdir)/strongswan.conf" || $(INSTALL) -o ${ipsecuid} -g ${ipsecgid} -m 640 $(srcdir)/strongswan.conf $(DESTDIR)$(sysconfdir)/strongswan.conf || true
