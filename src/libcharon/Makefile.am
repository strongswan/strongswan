ipseclib_LTLIBRARIES = libcharon.la

libcharon_la_SOURCES = \
bus/bus.c bus/bus.h \
bus/listeners/listener.h \
bus/listeners/file_logger.c bus/listeners/file_logger.h \
bus/listeners/sys_logger.c bus/listeners/sys_logger.h \
config/backend_manager.c config/backend_manager.h config/backend.h \
config/child_cfg.c config/child_cfg.h \
config/ike_cfg.c config/ike_cfg.h \
config/peer_cfg.c config/peer_cfg.h \
config/proposal.c config/proposal.h \
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
kernel/kernel_handler.c kernel/kernel_handler.h \
network/receiver.c network/receiver.h network/sender.c network/sender.h \
network/packet.c network/packet.h network/socket.c network/socket.h \
network/socket_manager.c network/socket_manager.h \
processing/jobs/acquire_job.c processing/jobs/acquire_job.h \
processing/jobs/delete_child_sa_job.c processing/jobs/delete_child_sa_job.h \
processing/jobs/delete_ike_sa_job.c processing/jobs/delete_ike_sa_job.h \
processing/jobs/migrate_job.c processing/jobs/migrate_job.h \
processing/jobs/process_message_job.c processing/jobs/process_message_job.h \
processing/jobs/rekey_child_sa_job.c processing/jobs/rekey_child_sa_job.h \
processing/jobs/rekey_ike_sa_job.c processing/jobs/rekey_ike_sa_job.h \
processing/jobs/retransmit_job.c processing/jobs/retransmit_job.h \
processing/jobs/send_dpd_job.c processing/jobs/send_dpd_job.h \
processing/jobs/send_keepalive_job.c processing/jobs/send_keepalive_job.h \
processing/jobs/start_action_job.c processing/jobs/start_action_job.h \
processing/jobs/roam_job.c processing/jobs/roam_job.h \
processing/jobs/update_sa_job.c processing/jobs/update_sa_job.h \
processing/jobs/inactivity_job.c processing/jobs/inactivity_job.h \
sa/authenticators/authenticator.c sa/authenticators/authenticator.h \
sa/authenticators/eap_authenticator.c sa/authenticators/eap_authenticator.h \
sa/authenticators/eap/eap_method.c sa/authenticators/eap/eap_method.h \
sa/authenticators/eap/eap_manager.c sa/authenticators/eap/eap_manager.h \
sa/authenticators/psk_authenticator.c sa/authenticators/psk_authenticator.h \
sa/authenticators/pubkey_authenticator.c sa/authenticators/pubkey_authenticator.h \
sa/child_sa.c sa/child_sa.h \
sa/ike_sa.c sa/ike_sa.h \
sa/ike_sa_id.c sa/ike_sa_id.h \
sa/ike_sa_manager.c sa/ike_sa_manager.h \
sa/task_manager.c sa/task_manager.h \
sa/keymat.c sa/keymat.h \
sa/shunt_manager.c sa/shunt_manager.h \
sa/trap_manager.c sa/trap_manager.h \
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
sa/tasks/ike_vendor.c sa/tasks/ike_vendor.h \
sa/tasks/task.c sa/tasks/task.h

daemon.lo :		$(top_builddir)/config.status

INCLUDES = \
	-I${linux_headers} \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DPLUGINS=\""${libcharon_plugins}\""

libcharon_la_LIBADD = -lm $(PTHREADLIB) $(DLLIB) $(SOCKLIB)

EXTRA_DIST = Android.mk

# compile options
#################

if USE_ME
  libcharon_la_SOURCES += encoding/payloads/endpoint_notify.c encoding/payloads/endpoint_notify.h \
    processing/jobs/initiate_mediation_job.c processing/jobs/initiate_mediation_job.h \
    processing/jobs/mediation_job.c processing/jobs/mediation_job.h \
    sa/connect_manager.c sa/connect_manager.h \
    sa/mediation_manager.c sa/mediation_manager.h \
    sa/tasks/ike_me.c sa/tasks/ike_me.h
endif

if USE_LIBCAP
  libcharon_la_LIBADD += -lcap
endif

# build optional plugins
########################

if MONOLITHIC
SUBDIRS =
else
SUBDIRS = .
endif

if USE_LOAD_TESTER
  SUBDIRS += plugins/load_tester
if MONOLITHIC
  libcharon_la_LIBADD += plugins/load_tester/libstrongswan-load-tester.la
endif
endif

if USE_SOCKET_DEFAULT
  SUBDIRS += plugins/socket_default
if MONOLITHIC
  libcharon_la_LIBADD += plugins/socket_default/libstrongswan-socket-default.la
endif
endif

if USE_SOCKET_RAW
  SUBDIRS += plugins/socket_raw
if MONOLITHIC
  libcharon_la_LIBADD += plugins/socket_raw/libstrongswan-socket-raw.la
endif
endif

if USE_SOCKET_DYNAMIC
  SUBDIRS += plugins/socket_dynamic
if MONOLITHIC
  libcharon_la_LIBADD += plugins/socket_dynamic/libstrongswan-socket-dynamic.la
endif
endif

if USE_FARP
  SUBDIRS += plugins/farp
if MONOLITHIC
  libcharon_la_LIBADD += plugins/farp/libstrongswan-farp.la
endif
endif

if USE_STROKE
  SUBDIRS += plugins/stroke
if MONOLITHIC
  libcharon_la_LIBADD += plugins/stroke/libstrongswan-stroke.la
endif
endif

if USE_SMP
  SUBDIRS += plugins/smp
if MONOLITHIC
  libcharon_la_LIBADD += plugins/smp/libstrongswan-smp.la
endif
endif

if USE_SQL
  SUBDIRS += plugins/sql
if MONOLITHIC
  libcharon_la_LIBADD += plugins/sql/libstrongswan-sql.la
endif
endif

if USE_UPDOWN
  SUBDIRS += plugins/updown
if MONOLITHIC
  libcharon_la_LIBADD += plugins/updown/libstrongswan-updown.la
endif
endif

if USE_EAP_IDENTITY
  SUBDIRS += plugins/eap_identity
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_identity/libstrongswan-eap-identity.la
endif
endif

if USE_EAP_SIM
  SUBDIRS += plugins/eap_sim
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_sim/libstrongswan-eap-sim.la
endif
endif

if USE_EAP_SIM_FILE
  SUBDIRS += plugins/eap_sim_file
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_sim_file/libstrongswan-eap-sim-file.la
endif
endif

if USE_EAP_SIM_PCSC
  SUBDIRS += plugins/eap_sim_pcsc
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_sim_pcsc/libstrongswan-eap-sim-pcsc.la
endif
endif

if USE_EAP_SIMAKA_SQL
  SUBDIRS += plugins/eap_simaka_sql
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_simaka_sql/libstrongswan-eap-simaka-sql.la
endif
endif

if USE_EAP_SIMAKA_PSEUDONYM
  SUBDIRS += plugins/eap_simaka_pseudonym
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_simaka_pseudonym/libstrongswan-eap-simaka-pseudonym.la
endif
endif

if USE_EAP_SIMAKA_REAUTH
  SUBDIRS += plugins/eap_simaka_reauth
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_simaka_reauth/libstrongswan-eap-simaka-reauth.la
endif
endif

if USE_EAP_AKA
  SUBDIRS += plugins/eap_aka
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_aka/libstrongswan-eap-aka.la
endif
endif

if USE_EAP_AKA_3GPP2
  SUBDIRS += plugins/eap_aka_3gpp2
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_aka_3gpp2/libstrongswan-eap-aka-3gpp2.la
endif
endif

if USE_SIMAKA
if MONOLITHIC
  # otherwise this library is linked to both the eap_aka and the eap_sim plugin
  libcharon_la_LIBADD += $(top_builddir)/src/libsimaka/libsimaka.la
endif
endif

if USE_EAP_MD5
  SUBDIRS += plugins/eap_md5
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_md5/libstrongswan-eap-md5.la
endif
endif

if USE_EAP_GTC
  SUBDIRS += plugins/eap_gtc
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_gtc/libstrongswan-eap-gtc.la
endif
endif

if USE_EAP_MSCHAPV2
  SUBDIRS += plugins/eap_mschapv2
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_mschapv2/libstrongswan-eap-mschapv2.la
endif
endif

if USE_EAP_RADIUS
  SUBDIRS += plugins/eap_radius
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_radius/libstrongswan-eap-radius.la
endif
endif

if USE_EAP_TLS
  SUBDIRS += plugins/eap_tls
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_tls/libstrongswan-eap-tls.la
endif
endif

if USE_EAP_TTLS
  SUBDIRS += plugins/eap_ttls
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_ttls/libstrongswan-eap-ttls.la
endif
endif

if USE_EAP_PEAP
  SUBDIRS += plugins/eap_peap
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_peap/libstrongswan-eap-peap.la
endif
endif

if USE_EAP_TNC
  SUBDIRS += plugins/eap_tnc
if MONOLITHIC
  libcharon_la_LIBADD += plugins/eap_tnc/libstrongswan-eap-tnc.la
endif
endif

if USE_TLS
if MONOLITHIC
  # otherwise this library is linked to eap_tls
  libcharon_la_LIBADD += $(top_builddir)/src/libtls/libtls.la
endif
endif

if USE_RADIUS
if MONOLITHIC
  # otherwise this library is linked to eap_radius
  libcharon_la_LIBADD += $(top_builddir)/src/libradius/libradius.la
endif
endif

if USE_TNC_IFMAP
  SUBDIRS += plugins/tnc_ifmap
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnc_ifmap/libstrongswan-tnc-ifmap.la
endif
endif

if USE_TNC_PDP
  SUBDIRS += plugins/tnc_pdp
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnc_pdp/libstrongswan-tnc-pdp.la
endif
endif

if USE_TNC_IMC
  SUBDIRS += plugins/tnc_imc
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnc_imc/libstrongswan-tnc-imc.la
endif
endif

if USE_TNC_IMV
  SUBDIRS += plugins/tnc_imv
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnc_imv/libstrongswan-tnc-imv.la
endif
endif

if USE_TNC_TNCCS
  SUBDIRS += plugins/tnc_tnccs
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnc_tnccs/libstrongswan-tnc-tnccs.la
endif
endif

if USE_TNCCS_11
  SUBDIRS += plugins/tnccs_11
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnccs_11/libstrongswan-tnccs-11.la
endif
endif

if USE_TNCCS_20
  SUBDIRS += plugins/tnccs_20
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnccs_20/libstrongswan-tnccs-20.la
endif
endif

if USE_TNCCS_DYNAMIC
  SUBDIRS += plugins/tnccs_dynamic
if MONOLITHIC
  libcharon_la_LIBADD += plugins/tnccs_dynamic/libstrongswan-tnccs-dynamic.la
endif
endif

if USE_LIBTNCCS
if MONOLITHIC
  # otherwise this library is linked to the respective plugins
  libcharon_la_LIBADD += $(top_builddir)/src/libtnccs/libtnccs.la
endif
endif

if USE_MEDSRV
  SUBDIRS += plugins/medsrv
if MONOLITHIC
  libcharon_la_LIBADD += plugins/medsrv/libstrongswan-medsrv.la
endif
endif

if USE_MEDCLI
  SUBDIRS += plugins/medcli
if MONOLITHIC
  libcharon_la_LIBADD += plugins/medcli/libstrongswan-medcli.la
endif
endif

if USE_NM
  SUBDIRS += plugins/nm
if MONOLITHIC
  libcharon_la_LIBADD += plugins/nm/libstrongswan-nm.la
endif
endif

if USE_DHCP
  SUBDIRS += plugins/dhcp
if MONOLITHIC
  libcharon_la_LIBADD += plugins/dhcp/libstrongswan-dhcp.la
endif
endif

if USE_ANDROID
  SUBDIRS += plugins/android
if MONOLITHIC
  libcharon_la_LIBADD += plugins/android/libstrongswan-android.la
endif
endif

if USE_MAEMO
  SUBDIRS += plugins/maemo
if MONOLITHIC
  libcharon_la_LIBADD += plugins/maemo/libstrongswan-maemo.la
endif
endif

if USE_HA
  SUBDIRS += plugins/ha
if MONOLITHIC
  libcharon_la_LIBADD += plugins/ha/libstrongswan-ha.la
endif
endif

if USE_WHITELIST
  SUBDIRS += plugins/whitelist
if MONOLITHIC
  libcharon_la_LIBADD += plugins/whitelist/libstrongswan-whitelist.la
endif
endif

if USE_CERTEXPIRE
  SUBDIRS += plugins/certexpire
if MONOLITHIC
  libcharon_la_LIBADD += plugins/certexpire/libstrongswan-certexpire.la
endif
endif

if USE_LED
  SUBDIRS += plugins/led
if MONOLITHIC
  libcharon_la_LIBADD += plugins/led/libstrongswan-led.la
endif
endif

if USE_DUPLICHECK
  SUBDIRS += plugins/duplicheck
if MONOLITHIC
  libcharon_la_LIBADD += plugins/duplicheck/libstrongswan-duplicheck.la
endif
endif

if USE_COUPLING
  SUBDIRS += plugins/coupling
if MONOLITHIC
  libcharon_la_LIBADD += plugins/coupling/libstrongswan-coupling.la
endif
endif

if USE_RADATTR
  SUBDIRS += plugins/radattr
if MONOLITHIC
  libcharon_la_LIBADD += plugins/radattr/libstrongswan-radattr.la
endif
endif

if USE_UCI
  SUBDIRS += plugins/uci
if MONOLITHIC
  libcharon_la_LIBADD += plugins/uci/libstrongswan-uci.la
endif
endif

if USE_ADDRBLOCK
  SUBDIRS += plugins/addrblock
if MONOLITHIC
  libcharon_la_LIBADD += plugins/uci/libstrongswan-addrblock.la
endif
endif

if USE_UNIT_TESTS
  SUBDIRS += plugins/unit_tester
if MONOLITHIC
  libcharon_la_LIBADD += plugins/unit_tester/libstrongswan-unit-tester.la
endif
endif

