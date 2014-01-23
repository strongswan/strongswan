# make this relative to the location of strongswan.conf
strongswanconfdir = `dirname $(strongswan_conf)`
strongswanddir = $(strongswanconfdir)/strongswan.d
charonconfdir = $(strongswanddir)/charon

options = \
	options/charon.opt

plugins = \
	plugins/test.opt

alloptions = $(options) $(plugins)

confsnippets = $(alloptions:opt=conf)

# we only install snippets for enabled plugins
plugins_install_tmp = $(charon_plugins:%=plugins/%.tmp)
plugins_install_src = $(charon_plugins:%=plugins/%.conf)

strongswand_DATA = $(options:opt=conf)
charonconf_DATA = $(plugins_install_src)

BUILT_SOURCES = default.conf $(confsnippets)
EXTRA_DIST = format-options.py strongswan.conf default.opt \
	default.conf $(alloptions) $(confsnippets)

.opt.conf:
	$(AM_V_GEN) \
	case "$<" in \
	*plugins/*) \
		sed \
		-e "s:\@PLUGIN_NAME\@:`basename $< .opt`:" \
		$(srcdir)/default.opt | cat - $< | \
		$(PYTHON) $(srcdir)/format-options.py -f conf -r charon.plugins > $(srcdir)/$@ \
		;; \
	*) \
		$(PYTHON) $(srcdir)/format-options.py -f conf -r charon.plugins $< > $(srcdir)/$@ \
		;; \
	esac

# we need another implicit rule to generate files from the generic template only
# if the rules above did not catch it.  this requires an intermediate step that
# generates a copy of the generic config template.
$(plugins_install_tmp):
	@cp $(srcdir)/default.conf $(srcdir)/$@

.tmp.conf:
	$(AM_V_GEN) \
	sed \
	-e "s:\@PLUGIN_NAME\@:`basename $< .tmp`:" \
	$(srcdir)/$< > $(srcdir)/$@

maintainer-clean-local:
	cd $(srcdir) && \
		rm -f $(confsnippets) default.conf plugins/*.conf plugins/*.tmp

install-exec-local:
	test -e "$(DESTDIR)${strongswanconfdir}" || $(INSTALL) -d "$(DESTDIR)$(strongswanconfdir)"
	test -e "$(DESTDIR)$(strongswanconfdir)/strongswan.conf" || $(INSTALL) -m 640 $(srcdir)/strongswan.conf $(DESTDIR)$(strongswanconfdir)/strongswan.conf || true

install-data-hook:
	chmod 0640 $(DESTDIR)$(strongswanddir)/*.conf
	chmod 0640 $(DESTDIR)$(charonconfdir)/*.conf
