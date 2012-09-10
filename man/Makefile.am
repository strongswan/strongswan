dist_man_MANS = ipsec.conf.5 ipsec.secrets.5 strongswan.conf.5
EXTRA_DIST = ipsec.conf.5.in ipsec.secrets.5.in strongswan.conf.5.in
CLEANFILES = ipsec.conf.5 ipsec.secrets.5 strongswan.conf.5

SUFFIXES = .in

.in:
	sed \
	-e "s:@IPSEC_VERSION@:$(PACKAGE_VERSION):" \
	-e "s:@DEV_URANDOM@:$(urandom_device):" \
	-e "s:@DEV_RANDOM@:$(random_device):" \
	$(srcdir)/$@.in > $@

