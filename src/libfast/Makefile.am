ipseclib_LTLIBRARIES = libfast.la

libfast_la_SOURCES = \
	dispatcher.c request.c session.c smtp.c

if USE_DEV_HEADERS
fast_includedir = ${dev_headers}/fast
nobase_fast_include_HEADERS = \
	context.h controller.h dispatcher.h filter.h request.h session.h smtp.h
endif

libfast_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la \
  -lfcgi $(clearsilver_LIBS) $(PTHREADLIB)
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I/usr/include/ClearSilver
AM_CFLAGS = -rdynamic
