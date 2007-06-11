

ipsec_PROGRAMS = charon

charon_SOURCES = \
bus/bus.c bus/bus.h \
bus/listeners/file_logger.c bus/listeners/file_logger.h \
bus/listeners/sys_logger.c bus/listeners/sys_logger.h \
config/backends/backend.h config/backends/writeable_backend.h \
config/backend_manager.c config/backend_manager.h \
config/child_cfg.c config/child_cfg.h \
config/credentials/local_credential_store.c config/credentials/local_credential_store.h \
config/ike_cfg.c config/ike_cfg.h \
config/peer_cfg.c config/peer_cfg.h \
config/proposal.c config/proposal.h \
config/traffic_selector.c config/traffic_selector.h \
control/interfaces/interface.h \
control/interface_manager.c control/interface_manager.h \
daemon.c daemon.h \
encoding/generator.c encoding/generator.h \
encoding/message.c encoding/message.h \
encoding/parser.c encoding/parser.h \
encoding/payloads/auth_payload.c encoding/payloads/auth_payload.h \
encoding/payloads/cert_payload.c encoding/payloads/cert_payload.h \
encoding/payloads/certreq_payload.c encoding/payloads/certreq_payload.h \
encoding/payloads/configuration_attribute.c encoding/payloads/configuration_attribute.h \
encoding/payloads/cp_payload.c encoding/payloads/cp_payload.h \
encoding/payloads/delete_payload.c encoding/payloads/delete_payload.h \
encoding/payloads/eap_payload.c encoding/payloads/eap_payload.h \
encoding/payloads/encodings.c encoding/payloads/encodings.h \
encoding/payloads/encryption_payload.c encoding/payloads/encryption_payload.h \
encoding/payloads/id_payload.c encoding/payloads/id_payload.h \
encoding/payloads/ike_header.c encoding/payloads/ike_header.h \
encoding/payloads/ke_payload.c  encoding/payloads/ke_payload.h \
encoding/payloads/nonce_payload.c encoding/payloads/nonce_payload.h \
encoding/payloads/notify_payload.c encoding/payloads/notify_payload.h \
encoding/payloads/payload.c encoding/payloads/payload.h \
encoding/payloads/proposal_substructure.c encoding/payloads/proposal_substructure.h \
encoding/payloads/sa_payload.c encoding/payloads/sa_payload.h \
encoding/payloads/traffic_selector_substructure.c encoding/payloads/traffic_selector_substructure.h \
encoding/payloads/transform_attribute.c encoding/payloads/transform_attribute.h \
encoding/payloads/transform_substructure.c encoding/payloads/transform_substructure.h \
encoding/payloads/ts_payload.c encoding/payloads/ts_payload.h \
encoding/payloads/unknown_payload.c encoding/payloads/unknown_payload.h \
encoding/payloads/vendor_id_payload.c encoding/payloads/vendor_id_payload.h \
kernel/kernel_interface.c kernel/kernel_interface.h \
network/packet.c network/packet.h \
network/receiver.c network/receiver.h \
network/sender.c network/sender.h \
network/socket.c network/socket.h \
processing/jobs/job.h \
processing/jobs/acquire_job.c processing/jobs/acquire_job.h \
processing/jobs/callback_job.c processing/jobs/callback_job.h \
processing/jobs/delete_child_sa_job.c processing/jobs/delete_child_sa_job.h \
processing/jobs/delete_ike_sa_job.c processing/jobs/delete_ike_sa_job.h \
processing/jobs/process_message_job.c processing/jobs/process_message_job.h \
processing/jobs/rekey_child_sa_job.c processing/jobs/rekey_child_sa_job.h \
processing/jobs/rekey_ike_sa_job.c processing/jobs/rekey_ike_sa_job.h \
processing/jobs/retransmit_job.c processing/jobs/retransmit_job.h \
processing/jobs/send_dpd_job.c processing/jobs/send_dpd_job.h \
processing/jobs/send_keepalive_job.c processing/jobs/send_keepalive_job.h \
processing/scheduler.c processing/scheduler.h \
processing/processor.c processing/processor.h  \
sa/authenticators/authenticator.c sa/authenticators/authenticator.h \
sa/authenticators/eap_authenticator.c sa/authenticators/eap_authenticator.h \
sa/authenticators/eap/eap_method.c sa/authenticators/eap/eap_method.h \
sa/authenticators/psk_authenticator.c sa/authenticators/psk_authenticator.h \
sa/authenticators/rsa_authenticator.c sa/authenticators/rsa_authenticator.h \
sa/child_sa.c sa/child_sa.h \
sa/ike_sa.c sa/ike_sa.h \
sa/ike_sa_id.c sa/ike_sa_id.h \
sa/ike_sa_manager.c sa/ike_sa_manager.h \
sa/task_manager.c sa/task_manager.h \
sa/tasks/child_create.c sa/tasks/child_create.h \
sa/tasks/child_delete.c sa/tasks/child_delete.h \
sa/tasks/child_rekey.c sa/tasks/child_rekey.h \
sa/tasks/ike_auth.c sa/tasks/ike_auth.h \
sa/tasks/ike_cert.c sa/tasks/ike_cert.h \
sa/tasks/ike_config.c sa/tasks/ike_config.h \
sa/tasks/ike_delete.c sa/tasks/ike_delete.h \
sa/tasks/ike_dpd.c sa/tasks/ike_dpd.h \
sa/tasks/ike_init.c sa/tasks/ike_init.h \
sa/tasks/ike_natd.c sa/tasks/ike_natd.h \
sa/tasks/ike_rekey.c sa/tasks/ike_rekey.h \
sa/tasks/task.c sa/tasks/task.h


INCLUDES = -I${linuxdir} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon -I$(top_srcdir)/src/stroke
AM_CFLAGS = -rdynamic -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\" \
	-DIPSEC_EAPDIR=\"${eapdir}\" -DIPSEC_BACKENDDIR=\"${backenddir}\" -DIPSEC_INTERFACEDIR=\"${interfacedir}\"
charon_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lgmp -lpthread -lm -ldl

if USE_LIBCURL
  charon_LDADD += -lcurl
endif


# build EAP plugins, EAP-Identity is always built
#################################################
eap_LTLIBRARIES =

eap_LTLIBRARIES += libeapidentity.la
libeapidentity_la_SOURCES = sa/authenticators/eap/eap_identity.h sa/authenticators/eap/eap_identity.c
libeapidentity_la_LDFLAGS = -module

if BUILD_EAP_SIM
  eap_LTLIBRARIES += libeapsim.la
  libeapsim_la_SOURCES = sa/authenticators/eap/eap_sim.h sa/authenticators/eap/eap_sim.c
  libeapsim_la_LDFLAGS = -module
endif

# build backends, local backend is always built
###############################################
backend_LTLIBRARIES =

backend_LTLIBRARIES += liblocal.la
liblocal_la_SOURCES = config/backends/local_backend.h config/backends/local_backend.c
liblocal_la_LDFLAGS = -module

# build control interfaces, stroke interface is always built
############################################################
interface_LTLIBRARIES =

interface_LTLIBRARIES += libstroke.la
libstroke_la_SOURCES = control/interfaces/stroke_interface.h control/interfaces/stroke_interface.c
libstroke_la_LDFLAGS = -module

if USE_LIBDBUS
  interface_LTLIBRARIES += libdbus.la
  libdbus_la_SOURCES = control/interfaces/dbus_interface.h control/interfaces/dbus_interface.c
  libdbus_la_LDFLAGS = -module
  libdbus_la_LIBADD = ${dbus_LIBS}
  INCLUDES += ${dbus_CFLAGS}
endif

if USE_LIBXML
  interface_LTLIBRARIES += libxml.la
  libxml_la_SOURCES = control/interfaces/xml_interface.h control/interfaces/xml_interface.c
  libxml_la_LDFLAGS = -module
  libxml_la_LIBADD = ${xml_LIBS}
  INCLUDES += ${xml_CFLAGS}
endif

