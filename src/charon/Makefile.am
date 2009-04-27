ipsec_PROGRAMS = charon

charon_SOURCES = \
bus/bus.c bus/bus.h \
bus/listeners/file_logger.c bus/listeners/file_logger.h \
bus/listeners/sys_logger.c bus/listeners/sys_logger.h \
config/backend_manager.c config/backend_manager.h config/backend.h \
config/child_cfg.c config/child_cfg.h \
config/ike_cfg.c config/ike_cfg.h \
config/peer_cfg.c config/peer_cfg.h \
config/proposal.c config/proposal.h config/proposal_keywords.c config/proposal_keywords.h \
config/auth_cfg.c config/auth_cfg.h \
config/traffic_selector.c config/traffic_selector.h \
config/attributes/attribute_provider.h \
config/attributes/attribute_handler.h \
config/attributes/attribute_manager.c config/attributes/attribute_manager.h \
control/controller.c control/controller.h \
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
kernel/kernel_ipsec.c kernel/kernel_ipsec.h \
kernel/kernel_net.h \
network/packet.c network/packet.h \
network/receiver.c network/receiver.h \
network/sender.c network/sender.h \
network/socket.h \
processing/jobs/job.h \
processing/jobs/acquire_job.c processing/jobs/acquire_job.h \
processing/jobs/callback_job.c processing/jobs/callback_job.h \
processing/jobs/delete_child_sa_job.c processing/jobs/delete_child_sa_job.h \
processing/jobs/delete_ike_sa_job.c processing/jobs/delete_ike_sa_job.h \
processing/jobs/migrate_job.c processing/jobs/migrate_job.h \
processing/jobs/process_message_job.c processing/jobs/process_message_job.h \
processing/jobs/rekey_child_sa_job.c processing/jobs/rekey_child_sa_job.h \
processing/jobs/rekey_ike_sa_job.c processing/jobs/rekey_ike_sa_job.h \
processing/jobs/retransmit_job.c processing/jobs/retransmit_job.h \
processing/jobs/send_dpd_job.c processing/jobs/send_dpd_job.h \
processing/jobs/send_keepalive_job.c processing/jobs/send_keepalive_job.h \
processing/jobs/roam_job.c processing/jobs/roam_job.h \
processing/jobs/update_sa_job.c processing/jobs/update_sa_job.h \
processing/scheduler.c processing/scheduler.h \
processing/processor.c processing/processor.h  \
sa/authenticators/authenticator.c sa/authenticators/authenticator.h \
sa/authenticators/eap_authenticator.c sa/authenticators/eap_authenticator.h \
sa/authenticators/eap/eap_method.c sa/authenticators/eap/eap_method.h \
sa/authenticators/eap/eap_manager.c sa/authenticators/eap/eap_manager.h \
sa/authenticators/eap/sim_manager.c sa/authenticators/eap/sim_manager.h \
sa/authenticators/psk_authenticator.c sa/authenticators/psk_authenticator.h \
sa/authenticators/pubkey_authenticator.c sa/authenticators/pubkey_authenticator.h \
sa/child_sa.c sa/child_sa.h \
sa/ike_sa.c sa/ike_sa.h \
sa/ike_sa_id.c sa/ike_sa_id.h \
sa/ike_sa_manager.c sa/ike_sa_manager.h \
sa/task_manager.c sa/task_manager.h \
sa/keymat.c sa/keymat.h \
sa/tasks/child_create.c sa/tasks/child_create.h \
sa/tasks/child_delete.c sa/tasks/child_delete.h \
sa/tasks/child_rekey.c sa/tasks/child_rekey.h \
sa/tasks/ike_auth.c sa/tasks/ike_auth.h \
sa/tasks/ike_cert_pre.c sa/tasks/ike_cert_pre.h \
sa/tasks/ike_cert_post.c sa/tasks/ike_cert_post.h \
sa/tasks/ike_config.c sa/tasks/ike_config.h \
sa/tasks/ike_delete.c sa/tasks/ike_delete.h \
sa/tasks/ike_dpd.c sa/tasks/ike_dpd.h \
sa/tasks/ike_init.c sa/tasks/ike_init.h \
sa/tasks/ike_natd.c sa/tasks/ike_natd.h \
sa/tasks/ike_mobike.c sa/tasks/ike_mobike.h \
sa/tasks/ike_rekey.c sa/tasks/ike_rekey.h \
sa/tasks/ike_reauth.c sa/tasks/ike_reauth.h \
sa/tasks/ike_auth_lifetime.c sa/tasks/ike_auth_lifetime.h \
sa/tasks/task.c sa/tasks/task.h \
credentials/credential_manager.c credentials/credential_manager.h \
credentials/sets/auth_cfg_wrapper.c credentials/sets/auth_cfg_wrapper.h \
credentials/sets/ocsp_response_wrapper.c credentials/sets/ocsp_response_wrapper.h \
credentials/sets/cert_cache.c credentials/sets/cert_cache.h \
credentials/credential_set.h

INCLUDES = -I${linuxdir} -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon
AM_CFLAGS = -rdynamic \
  -DIPSEC_DIR=\"${ipsecdir}\" \
  -DIPSEC_PIDDIR=\"${piddir}\" \
  -DIPSEC_PLUGINDIR=\"${plugindir}\" \
  -DSTRONGSWAN_CONF=\"${strongswan_conf}\"
charon_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lpthread -lm -ldl

EXTRA_DIST = config/proposal_keywords.txt
MAINTAINERCLEANFILES = config/proposal_keywords.c

config/proposal_keywords.c:	config/proposal_keywords.txt config/proposal_keywords.h
		(cd `dirname $<` && $(GPERF) -C -G -c -t < `basename $<` > `basename $@` )

# compile options
#################

# Use RAW socket if pluto gets built
if USE_PLUTO
  charon_SOURCES += network/socket-raw.c
else
  charon_SOURCES += network/socket.c
endif

if USE_ME
  charon_SOURCES += encoding/payloads/endpoint_notify.c encoding/payloads/endpoint_notify.h \
    processing/jobs/initiate_mediation_job.c processing/jobs/initiate_mediation_job.h \
    processing/jobs/mediation_job.c processing/jobs/mediation_job.h \
    sa/connect_manager.c sa/connect_manager.h \
    sa/mediation_manager.c sa/mediation_manager.h \
    sa/tasks/ike_me.c sa/tasks/ike_me.h
endif

if USE_INTEGRITY_TEST
  AM_CFLAGS += -DINTEGRITY_TEST
endif

if USE_SELF_TEST
  AM_CFLAGS += -DSELF_TEST
endif

if USE_CAPABILITIES
  charon_LDADD += -lcap
endif


# build optional plugins
########################

SUBDIRS = . 
PLUGINS = ${libstrongswan_plugins}

if USE_LOAD_TESTS
  SUBDIRS += plugins/load_tester
  PLUGINS += load-tester
endif

if USE_KERNEL_PFKEY
  SUBDIRS += plugins/kernel_pfkey
  PLUGINS += kernel-pfkey
endif

if USE_KERNEL_KLIPS
  SUBDIRS += plugins/kernel_klips
  PLUGINS += kernel-klips
endif

if USE_KERNEL_NETLINK
  SUBDIRS += plugins/kernel_netlink
  PLUGINS += kernel-netlink
endif

if USE_STROKE
  SUBDIRS += plugins/stroke
  PLUGINS += stroke
endif

if USE_SMP
  SUBDIRS += plugins/smp
  PLUGINS += smp
endif

if USE_SQL
  SUBDIRS += plugins/sql
  PLUGINS += sql
endif

if USE_UPDOWN
  SUBDIRS += plugins/updown
  PLUGINS += updown
endif

if USE_ATTR
  SUBDIRS += plugins/attr
  PLUGINS += attr
endif

if USE_EAP_IDENTITY
  SUBDIRS += plugins/eap_identity
  PLUGINS += eapidentity
endif

if USE_EAP_SIM
  SUBDIRS += plugins/eap_sim
  PLUGINS += eapsim
endif

if USE_EAP_SIM_FILE
  SUBDIRS += plugins/eap_sim_file
  PLUGINS += eapsim-file
endif

if USE_EAP_MD5
  SUBDIRS += plugins/eap_md5
  PLUGINS += eapmd5
endif

if USE_EAP_GTC
  SUBDIRS += plugins/eap_gtc
  PLUGINS += eapgtc
endif

if USE_EAP_AKA
  SUBDIRS += plugins/eap_aka
  PLUGINS += eapaka
endif

if USE_EAP_MSCHAPV2
  SUBDIRS += plugins/eap_mschapv2
  PLUGINS += eapmschapv2
endif

if USE_EAP_RADIUS
  SUBDIRS += plugins/eap_radius
  PLUGINS += eapradius
endif

if USE_MEDSRV
  SUBDIRS += plugins/medsrv
  PLUGINS += medsrv
endif

if USE_MEDCLI
  SUBDIRS += plugins/medcli
  PLUGINS += medcli
endif

if USE_NM
  SUBDIRS += plugins/nm
  PLUGINS += nm
endif

if USE_RESOLV_CONF
  SUBDIRS += plugins/resolv_conf
  PLUGINS += resolv-conf
endif

if USE_UCI
  SUBDIRS += plugins/uci
  PLUGINS += uci
endif

if USE_UNIT_TESTS
  SUBDIRS += plugins/unit_tester
  PLUGINS += unit-tester
endif

AM_CFLAGS += -DPLUGINS=\""${PLUGINS}\""

