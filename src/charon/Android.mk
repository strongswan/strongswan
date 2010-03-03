LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# copy-n-paste from Makefile.am
LOCAL_SRC_FILES := \
	bus/bus.c bus/bus.h \
	bus/listeners/listener.h \
	bus/listeners/file_logger.c bus/listeners/file_logger.h \
	bus/listeners/sys_logger.c bus/listeners/sys_logger.h \
	config/backend_manager.c config/backend_manager.h config/backend.h \
	config/child_cfg.c config/child_cfg.h \
	config/ike_cfg.c config/ike_cfg.h \
	config/peer_cfg.c config/peer_cfg.h \
	config/proposal.c config/proposal.h \
	config/auth_cfg.c config/auth_cfg.h \
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
	network/socket_manager.c network/socket_manager.h network/socket.h \
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
	processing/jobs/inactivity_job.c processing/jobs/inactivity_job.h \
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
	sa/tasks/task.c sa/tasks/task.h \
	credentials/credential_manager.c credentials/credential_manager.h \
	credentials/sets/auth_cfg_wrapper.c credentials/sets/auth_cfg_wrapper.h \
	credentials/sets/ocsp_response_wrapper.c credentials/sets/ocsp_response_wrapper.h \
	credentials/sets/cert_cache.c credentials/sets/cert_cache.h \
	credentials/credential_set.h

# adding the plugin source files (copy-n-paste from Makefile.am)

LOCAL_SRC_FILES += $(call add_plugin, android, \
	android_plugin.c android_plugin.h \
	android_handler.c android_handler.h \
)
ifneq ($(call plugin_enabled, android)),)
LOCAL_SHARED_LIBRARIES += libcutils
endif

LOCAL_SRC_FILES += $(call add_plugin, attr, \
	attr_plugin.h attr_plugin.c \
	attr_provider.h attr_provider.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-aka, \
	eap_aka_plugin.h eap_aka_plugin.c \
	eap_aka_peer.h eap_aka_peer.c \
	eap_aka_server.h eap_aka_server.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-aka-3gpp2, \
	eap_aka_3gpp2_plugin.h eap_aka_3gpp2_plugin.c \
	eap_aka_3gpp2_card.h eap_aka_3gpp2_card.c \
	eap_aka_3gpp2_provider.h eap_aka_3gpp2_provider.c \
	eap_aka_3gpp2_functions.h eap_aka_3gpp2_functions.c \
)
ifneq ($(call plugin_enabled, eap-aka-3gpp2)),)
LOCAL_C_INCLUDES += $(libgmp_PATH)
LOCAL_STATIC_LIBRARIES += libgmp
endif

LOCAL_SRC_FILES += $(call add_plugin, eap-gtc, \
	eap_gtc_plugin.h eap_gtc_plugin.c eap_gtc.h eap_gtc.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-identity, \
	eap_identity_plugin.h eap_identity_plugin.c eap_identity.h eap_identity.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-md5, \
	eap_md5_plugin.h eap_md5_plugin.c eap_md5.h eap_md5.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-mschapv2, \
	eap_mschapv2_plugin.h eap_mschapv2_plugin.c \
	eap_mschapv2.h eap_mschapv2.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-sim, \
	eap_sim_plugin.h eap_sim_plugin.c \
	eap_sim_peer.h eap_sim_peer.c \
	eap_sim_server.h eap_sim_server.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-simaka-pseudonym, \
	eap_simaka_pseudonym_plugin.h eap_simaka_pseudonym_plugin.c \
	eap_simaka_pseudonym_card.h eap_simaka_pseudonym_card.c \
	eap_simaka_pseudonym_provider.h eap_simaka_pseudonym_provider.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-simaka-reauth, \
	eap_simaka_reauth_plugin.h eap_simaka_reauth_plugin.c \
	eap_simaka_reauth_card.h eap_simaka_reauth_card.c \
	eap_simaka_reauth_provider.h eap_simaka_reauth_provider.c \
)

LOCAL_SRC_FILES += $(call add_plugin, eap-sim-file, \
	eap_sim_file_plugin.h eap_sim_file_plugin.c \
	eap_sim_file_card.h eap_sim_file_card.c \
	eap_sim_file_provider.h eap_sim_file_provider.c \
	eap_sim_file_triplets.h eap_sim_file_triplets.c \
)

# adding libakasim if either eap-aka or eap-sim is enabled
ifneq ($(or $(call plugin_enabled, eap-aka), $(call plugin_enabled, eap-sim)),)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../libsimaka/
LOCAL_SRC_FILES += $(addprefix ../libsimaka/, \
		simaka_message.h simaka_message.c \
		simaka_crypto.h simaka_crypto.c \
	)
endif

LOCAL_SRC_FILES += $(call add_plugin, kernel-netlink, \
	kernel_netlink_plugin.h kernel_netlink_plugin.c \
	kernel_netlink_ipsec.h kernel_netlink_ipsec.c kernel_netlink_net.h kernel_netlink_net.c \
	kernel_netlink_shared.h kernel_netlink_shared.c \
)

LOCAL_SRC_FILES += $(call add_plugin, load-tester, \
	load_tester_plugin.c load_tester_plugin.h \
	load_tester_config.c load_tester_config.h \
	load_tester_creds.c load_tester_creds.h \
	load_tester_ipsec.c load_tester_ipsec.h \
	load_tester_listener.c load_tester_listener.h \
	load_tester_diffie_hellman.c load_tester_diffie_hellman.h \
)

LOCAL_SRC_FILES += $(call add_plugin, socket-default, \
	socket_default_socket.h socket_default_socket.c \
	socket_default_plugin.h socket_default_plugin.c \
)

LOCAL_SRC_FILES += $(call add_plugin, socket-dynamic, \
	socket_dynamic_plugin.h socket_dynamic_plugin.c \
	socket_dynamic_socket.h socket_dynamic_socket.c \
)

# build charon -----------------------------------------------------------------

LOCAL_C_INCLUDES += \
	$(libvstr_PATH) \
	external/strongswan/src/include \
	external/strongswan/src/libstrongswan

LOCAL_CFLAGS := $(strongswan_CFLAGS)

# this is required to be able load the plugins
LOCAL_LDFLAGS := -Wl,--export-dynamic

LOCAL_MODULE := charon

LOCAL_ARM_MODE := arm

LOCAL_PRELINK_MODULE := false

LOCAL_SHARED_LIBRARIES += libstrongswan

include $(BUILD_EXECUTABLE)

