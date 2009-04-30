ipsec_SCRIPTS = _updown
CLEANFILES = _updown
dist_man8_MANS = _updown.8
EXTRA_DIST = _updown.in

_updown : _updown.in
	sed \
	-e "s:@IPSEC_SBINDIR@:$(sbindir):" \
	-e "s:\@IPSEC_ROUTING_TABLE\@:$(IPSEC_ROUTING_TABLE):" \
	-e "s:\@IPSEC_ROUTING_TABLE_PRIO\@:$(IPSEC_ROUTING_TABLE_PRIO):" \
	$(srcdir)/$@.in > $@
	chmod +x $@
