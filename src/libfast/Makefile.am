ipseclib_LTLIBRARIES = libfast.la

libfast_la_SOURCES = context.h dispatcher.c request.h session.h \
  controller.h dispatcher.h request.c session.c filter.h smtp.c smtp.h
libfast_la_LIBADD = $(top_builddir)/src/libstrongswan/libstrongswan.la \
  -lfcgi $(clearsilver_LIBS) $(PTHREADLIB)
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I/usr/include/ClearSilver
AM_CFLAGS = -rdynamic
