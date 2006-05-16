sbin_SCRIPTS = ipsec
CLEANFILES = ipsec
dist_man8_MANS = ipsec.8
EXTRA_DIST = ipsec.in

ipsec : ipsec.in
	sed \
	-e "s:@IPSEC_VERSION@:$(PACKAGE_VERSION):" \
	-e "s:@IPSEC_NAME@:$(PACKAGE_NAME):" \
	-e "s:@IPSEC_DISTRO@::" \
	-e "s:@IPSEC_DIR@:$(ipsecdir):" \
	-e "s:@IPSEC_SBINDIR@:$(sbindir):" \
	-e "s:@IPSEC_CONFDIR@:$(confdir):" \
	-e "s:@IPSEC_PIDDIR@:$(piddir):" \
	$< > $@
	chmod +x $@
