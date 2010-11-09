ipsec_PROGRAMS = conftest

AM_CFLAGS = -rdynamic

conftest_SOURCES = conftest.c conftest.h config.c config.h actions.c actions.h \
	hooks/hook.h hooks/ike_auth_fill.c hooks/unsort_message.c \
	hooks/add_notify.c hooks/unencrypted_notify.c hooks/ignore_message.c

INCLUDES = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

conftest_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lm $(PTHREADLIB) $(DLLIB)

EXTRA_DIST = suiteb README
