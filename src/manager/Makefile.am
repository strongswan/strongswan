ipsec_PROGRAMS = manager.fcgi

manager_fcgi_SOURCES = \
main.c manager.c manager.h gateway.h gateway.c storage.h storage.c xml.h xml.c \
controller/auth_controller.c controller/auth_controller.h \
controller/ikesa_controller.c controller/ikesa_controller.h \
controller/control_controller.c controller/control_controller.h \
controller/config_controller.c controller/config_controller.h \
controller/gateway_controller.c controller/gateway_controller.h

manager_fcgi_LDADD = $(top_builddir)/src/libfast/libfast.la ${xml_LIBS}

INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/libfast ${xml_CFLAGS}
AM_CFLAGS = -rdynamic -DIPSECDIR=\"${ipsecdir}\" -DIPSEC_PIDDIR=\"${piddir}\"

ipsec_DATA = manager.db

# Don't forget to add templates to EXTRA_DIST !!! How to automate?
ipsec_templatesdir = ${ipsecdir}/templates
ipsec_templates_DATA = templates/header.cs templates/footer.cs templates/error.cs

ipsec_templates_authdir = ${ipsec_templatesdir}/auth
ipsec_templates_auth_DATA = templates/auth/login.cs

ipsec_templates_gatewaydir = ${ipsec_templatesdir}/gateway
ipsec_templates_gateway_DATA = templates/gateway/list.cs

ipsec_templates_ikesadir = ${ipsec_templatesdir}/ikesa
ipsec_templates_ikesa_DATA = templates/ikesa/list.cs

ipsec_templates_controldir = ${ipsec_templatesdir}/control
ipsec_templates_control_DATA = templates/control/result.cs

ipsec_templates_configdir = ${ipsec_templatesdir}/config
ipsec_templates_config_DATA = templates/config/list.cs

ipsec_templates_staticdir = ${ipsec_templatesdir}/static
ipsec_templates_static_DATA = templates/static/style.css templates/static/script.js templates/static/jquery.js \
templates/static/pipe.png templates/static/pipe-good.png templates/static/pipe-bad.png \
templates/static/pipe-thin.png templates/static/pipe-thin-left.png templates/static/pipe-thin-right.png \
templates/static/pipe-thin-green.png templates/static/pipe-thin-left-green.png templates/static/pipe-thin-right-green.png \
templates/static/gateway-left.png templates/static/client-left.png templates/static/strongswan.png \
templates/static/router.png templates/static/gateway-right.png templates/static/client-right.png \
templates/static/close.png templates/static/initiate.png

EXTRA_DIST = manager.db templates/header.cs templates/footer.cs templates/error.cs \
templates/auth/login.cs templates/gateway/list.cs templates/ikesa/list.cs \
templates/config/list.cs templates/control/result.cs \
templates/static/style.css templates/static/script.js templates/static/jquery.js \
templates/static/pipe.png templates/static/pipe-good.png templates/static/pipe-bad.png \
templates/static/pipe-thin.png templates/static/pipe-thin-left.png templates/static/pipe-thin-right.png \
templates/static/pipe-thin-green.png templates/static/pipe-thin-left-green.png templates/static/pipe-thin-right-green.png \
templates/static/gateway-left.png templates/static/client-left.png templates/static/strongswan.png \
templates/static/router.png templates/static/gateway-right.png templates/static/client-right.png \
templates/static/close.png templates/static/initiate.png
