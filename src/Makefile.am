SUBDIRS = . include

if USE_LIBSTRONGSWAN
  SUBDIRS += libstrongswan
endif

if USE_LIBHYDRA
  SUBDIRS += libhydra
endif

if USE_LIBIPSEC
  SUBDIRS += libipsec
endif

if USE_SIMAKA
  SUBDIRS += libsimaka
endif

if USE_TLS
  SUBDIRS += libtls
endif

if USE_RADIUS
  SUBDIRS += libradius
endif

if USE_LIBTNCIF
  SUBDIRS += libtncif
endif

if USE_LIBTNCCS
  SUBDIRS += libtnccs
endif

if USE_LIBPTTLS
  SUBDIRS += libpttls
endif

if USE_IMCV
  SUBDIRS += libimcv
endif

if USE_PTS
  SUBDIRS += libpts
endif

if USE_LIBCHARON
  SUBDIRS += libcharon
endif

if USE_FILE_CONFIG
  SUBDIRS += starter
endif

if USE_IPSEC_SCRIPT
  SUBDIRS += ipsec _copyright
endif

if USE_CHARON
  SUBDIRS += charon
endif

if USE_NM
  SUBDIRS += charon-nm
endif

if USE_STROKE
  SUBDIRS += stroke
endif

if USE_UPDOWN
  SUBDIRS += _updown _updown_espmark
endif

if USE_TOOLS
  SUBDIRS += openac scepclient pki
endif

if USE_CONFTEST
  SUBDIRS += conftest
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

if USE_ATTR_SQL
  SUBDIRS += pool
endif

if USE_TKM
  SUBDIRS += charon-tkm
endif

if USE_CMD
  SUBDIRS += charon-cmd
endif

if USE_LIBPTTLS
  SUBDIRS += pt-tls-client
endif

EXTRA_DIST = strongswan.conf

install-exec-local :
		test -e "$(DESTDIR)${sysconfdir}" || $(INSTALL) -d "$(DESTDIR)$(sysconfdir)"
		test -e "$(DESTDIR)$(sysconfdir)/strongswan.conf" || $(INSTALL) -m 640 $(srcdir)/strongswan.conf $(DESTDIR)$(sysconfdir)/strongswan.conf || true
