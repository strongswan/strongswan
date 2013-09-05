ipsec_PROGRAMS = pool

pool_SOURCES = \
	pool.c pool_attributes.c pool_attributes.h \
	pool_usage.h pool_usage.c

pool.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-DPLUGINS=\""${pool_plugins}\""

pool_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la
