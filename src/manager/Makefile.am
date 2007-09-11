ipsec_PROGRAMS = manager

manager_SOURCES = \
main.c manager.c manager.h gateway.h gateway.c database.h database.c \
controller/auth_controller.c controller/auth_controller.h \
controller/static_controller.c controller/static_controller.h \
controller/status_controller.c controller/status_controller.h \
controller/gateway_controller.c controller/gateway_controller.h

manager_LDADD = $(top_builddir)/src/manager/libappserv.la -lsqlite3



lib_LTLIBRARIES = libappserv.la

libappserv_la_SOURCES = \
lib/context.h lib/dispatcher.c lib/request.h lib/response.h lib/session.h \
lib/controller.h lib/dispatcher.h lib/request.c lib/response.c lib/session.c \
lib/template.h lib/template.c

libappserv_la_LDFLAGS = -lstrongswan -lfcgi -lpthread -lneo_cs -lneo_utl

INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/manager/lib -I/usr/include/ClearSilver


ipsec_templatesdir = ${ipsecdir}/templates
ipsec_templates_DATA = templates/header.cs templates/footer.cs

ipsec_templates_authdir = ${ipsec_templatesdir}/auth
ipsec_templates_auth_DATA = templates/auth/login.cs templates/auth/logout.cs

ipsec_templates_staticdir = ${ipsec_templatesdir}/static
ipsec_templates_static_DATA = templates/static/style.css
