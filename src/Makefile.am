SUBDIRS = include

if USE_FILE_CONFIG
  SUBDIRS += libfreeswan starter ipsec _copyright
endif

if USE_LIBSTRONGSWAN
  SUBDIRS += libstrongswan
endif

if USE_PLUTO
  SUBDIRS += libcrypto pluto whack
endif
if USE_CHARON
  SUBDIRS += charon
endif

if USE_STROKE
  SUBDIRS += stroke
endif

if USE_PLUTO_OR_CHARON
  SUBDIRS += _updown _updown_espmark
endif

if USE_TOOLS
  SUBDIRS += openac scepclient
endif

if USE_UML
  SUBDIRS += dumm
endif

if USE_MANAGER
  SUBDIRS += manager
endif

if USE_FILE_CONFIG
install-exec-local :
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/cacerts
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/ocspcerts
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/certs
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/acerts
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/aacerts
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/crls
	mkdir -p -m 755 $(DESTDIR)$(confdir)/ipsec.d/reqs
	mkdir -p -m 700 $(DESTDIR)$(confdir)/ipsec.d/private
endif

