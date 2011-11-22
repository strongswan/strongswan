sbin_SCRIPTS = ipsec
CLEANFILES = ipsec ipsec.8
dist_man8_MANS = ipsec.8
EXTRA_DIST = ipsec.in ipsec.8.in Android.mk

ipsec.8 : ipsec.8.in
	sed \
	-e "s:@IPSEC_VERSION@:$(PACKAGE_VERSION):" \
	$(srcdir)/$@.in > $@

ipsec : ipsec.in
	sed \
	-e "s:@IPSEC_SHELL@:/bin/sh:" \
	-e "s:@IPSEC_VERSION@:$(PACKAGE_VERSION):" \
	-e "s:@IPSEC_NAME@:$(PACKAGE_NAME):" \
	-e "s:@IPSEC_DISTRO@::" \
	-e "s:@IPSEC_DIR@:$(ipsecdir):" \
	-e "s:@IPSEC_SBINDIR@:$(sbindir):" \
	-e "s:@IPSEC_CONFDIR@:$(sysconfdir):" \
	-e "s:@IPSEC_PIDDIR@:$(piddir):" \
	$(srcdir)/$@.in > $@
	chmod +x $@
