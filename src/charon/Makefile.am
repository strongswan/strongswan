SUBDIRS = . testing
ipsec_PROGRAMS = charon

charon_SOURCES = \
config/connections/connection.c config/connections/connection.h config/connections/local_connection_store.c \
config/connections/connection_store.h config/connections/local_connection_store.h config/policies/policy.c \
config/policies/policy.h config/policies/policy_store.h config/policies/local_policy_store.c \
config/policies/local_policy_store.h config/credentials/local_credential_store.c \
config/credentials/local_credential_store.h config/credentials/credential_store.h config/traffic_selector.c \
config/traffic_selector.h config/proposal.c config/proposal.h config/configuration.c config/configuration.h \
sa/states/state.c sa/states/state.h sa/states/ike_sa_init_requested.c sa/states/ike_sa_init_requested.h \
sa/states/ike_sa_init_responded.c sa/states/ike_sa_established.c sa/states/ike_sa_established.h \
sa/states/responder_init.c sa/states/responder_init.h sa/states/initiator_init.c sa/states/initiator_init.h \
sa/states/ike_sa_init_responded.h sa/states/ike_auth_requested.c sa/states/ike_auth_requested.h \
sa/states/delete_requested.h sa/states/delete_requested.c \
sa/child_sa.c sa/child_sa.h sa/ike_sa.c sa/ike_sa.h sa/ike_sa_manager.c sa/ike_sa_manager.h \
sa/ike_sa_id.c sa/ike_sa_id.h sa/authenticator.c sa/authenticator.h encoding/payloads/encryption_payload.c \
encoding/payloads/cert_payload.c encoding/payloads/payload.h encoding/payloads/traffic_selector_substructure.c \
encoding/payloads/configuration_attribute.h encoding/payloads/proposal_substructure.h \
encoding/payloads/transform_attribute.c encoding/payloads/transform_attribute.h \
encoding/payloads/configuration_attribute.c encoding/payloads/transform_substructure.c \
encoding/payloads/encryption_payload.h encoding/payloads/auth_payload.c encoding/payloads/ike_header.c \
encoding/payloads/transform_substructure.h encoding/payloads/nonce_payload.c encoding/payloads/cert_payload.h \
encoding/payloads/eap_payload.c encoding/payloads/ike_header.h encoding/payloads/auth_payload.h \
encoding/payloads/ts_payload.c encoding/payloads/traffic_selector_substructure.h encoding/payloads/nonce_payload.h \
encoding/payloads/notify_payload.c encoding/payloads/eap_payload.h encoding/payloads/notify_payload.h \
encoding/payloads/ts_payload.h encoding/payloads/id_payload.c encoding/payloads/ke_payload.c \
encoding/payloads/unknown_payload.c encoding/payloads/encodings.c encoding/payloads/id_payload.h \
encoding/payloads/cp_payload.c encoding/payloads/delete_payload.c encoding/payloads/sa_payload.c \
encoding/payloads/ke_payload.h encoding/payloads/unknown_payload.h encoding/payloads/encodings.h \
encoding/payloads/certreq_payload.c encoding/payloads/cp_payload.h encoding/payloads/delete_payload.h \
encoding/payloads/sa_payload.h encoding/payloads/vendor_id_payload.c encoding/payloads/certreq_payload.h \
encoding/payloads/vendor_id_payload.h encoding/payloads/proposal_substructure.c encoding/payloads/payload.c \
encoding/parser.h encoding/message.c encoding/generator.c encoding/message.h encoding/generator.h \
encoding/parser.c daemon.c daemon.h network/packet.c \
network/socket.c network/packet.h network/socket.h queues/jobs/job.h queues/jobs/job.c \
queues/jobs/delete_established_ike_sa_job.c queues/jobs/retransmit_request_job.h queues/jobs/initiate_ike_sa_job.h \
queues/jobs/incoming_packet_job.c queues/jobs/delete_half_open_ike_sa_job.c \
queues/jobs/delete_established_ike_sa_job.h queues/jobs/delete_half_open_ike_sa_job.h \
queues/jobs/incoming_packet_job.h queues/jobs/retransmit_request_job.c queues/jobs/initiate_ike_sa_job.c \
queues/job_queue.c queues/event_queue.c queues/send_queue.h queues/job_queue.h queues/event_queue.h \
queues/send_queue.c threads/kernel_interface.c threads/thread_pool.c threads/scheduler.c threads/sender.c \
threads/sender.h threads/kernel_interface.h threads/scheduler.h threads/receiver.c threads/stroke_interface.c \
threads/thread_pool.h threads/receiver.h threads/stroke_interface.h

INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon -I$(top_srcdir)/src/stroke
AM_CFLAGS = -DIPSEC_CONFDIR=\"${confdir}\" -DIPSEC_PIDDIR=\"${piddir}\"
charon_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lgmp -lpthread
