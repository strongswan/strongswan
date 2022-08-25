ipsec_SCRIPTS = _updownv2
CLEANFILES = _updownv2
EXTRA_DIST = _updownv2.in

_updownv2 : _updownv2.in
	$(AM_V_GEN) \
	sed \
	-e "s:\@sbindir\@:$(sbindir):" \
	-e "s:\@routing_table\@:$(routing_table):" \
	-e "s:\@routing_table_prio\@:$(routing_table_prio):" \
	$(srcdir)/$@.in > $@
	chmod +x $@
