noinst_PROGRAMS = testing
INCLUDES = -I$(top_srcdir)/src/libstrongswan -I$(top_srcdir)/src/charon -I$(top_srcdir)/src/stroke

testing_SOURCES = \
thread_pool_test.c policy_test.c prf_plus_test.h testcases.c ike_sa_manager_test.c \
linked_list_test.c send_queue_test.h policy_test.h encryption_payload_test.c thread_pool_test.h \
child_sa_test.c linked_list_test.h packet_test.c child_sa_test.h encryption_payload_test.h packet_test.h \
diffie_hellman_test.c event_queue_test.c event_queue_test.h socket_test.c Makefile.am identification_test.c \
ike_sa_manager_test.h ike_sa_test.c diffie_hellman_test.h parser_test.c socket_test.h identification_test.h \
connection_test.c proposal_test.c ike_sa_test.h kernel_interface_test.c parser_test.h connection_test.h \
proposal_test.h kernel_interface_test.h ike_sa_id_test.c hmac_test.c leak_detective_test.c hasher_test.c \
ike_sa_id_test.h hmac_test.h leak_detective_test.h job_queue_test.c scheduler_test.c hmac_signer_test.c \
hasher_test.h sender_test.c certificate_test.c job_queue_test.h scheduler_test.h hmac_signer_test.h \
rsa_test.c sender_test.h generator_test.c aes_cbc_crypter_test.c certificate_test.h prf_plus_test.c \
rsa_test.h generator_test.h aes_cbc_crypter_test.h send_queue_test.c

testing_LDADD = $(top_builddir)/src/libstrongswan/libstrongswan.la -lgmp -lpthread \
$(top_srcdir)/src/charon/connection.o $(top_srcdir)/src/charon/local_connection_store.o $(top_srcdir)/src/charon/policy.o \
$(top_srcdir)/src/charon/local_policy_store.o $(top_srcdir)/src/charon/local_credential_store.o $(top_srcdir)/src/charon/traffic_selector.o \
$(top_srcdir)/src/charon/proposal.o $(top_srcdir)/src/charon/configuration.o $(top_srcdir)/src/charon/state.o $(top_srcdir)/src/charon/ike_sa_init_requested.o \
$(top_srcdir)/src/charon/ike_sa_init_responded.o $(top_srcdir)/src/charon/ike_sa_established.o $(top_srcdir)/src/charon/responder_init.o \
$(top_srcdir)/src/charon/initiator_init.o $(top_srcdir)/src/charon/ike_auth_requested.o $(top_srcdir)/src/charon/delete_ike_sa_requested.o \
$(top_srcdir)/src/charon/child_sa.o $(top_srcdir)/src/charon/ike_sa.o $(top_srcdir)/src/charon/ike_sa_manager.o $(top_srcdir)/src/charon/ike_sa_id.o \
$(top_srcdir)/src/charon/authenticator.o $(top_srcdir)/src/charon/encryption_payload.o $(top_srcdir)/src/charon/cert_payload.o \
$(top_srcdir)/src/charon/traffic_selector_substructure.o $(top_srcdir)/src/charon/transform_attribute.o $(top_srcdir)/src/charon/configuration_attribute.o \
$(top_srcdir)/src/charon/transform_substructure.o $(top_srcdir)/src/charon/auth_payload.o $(top_srcdir)/src/charon/ike_header.o $(top_srcdir)/src/charon/nonce_payload.o \
$(top_srcdir)/src/charon/eap_payload.o $(top_srcdir)/src/charon/ts_payload.o $(top_srcdir)/src/charon/notify_payload.o $(top_srcdir)/src/charon/id_payload.o \
$(top_srcdir)/src/charon/ke_payload.o $(top_srcdir)/src/charon/unknown_payload.o $(top_srcdir)/src/charon/encodings.o $(top_srcdir)/src/charon/cp_payload.o \
$(top_srcdir)/src/charon/delete_payload.o $(top_srcdir)/src/charon/sa_payload.o $(top_srcdir)/src/charon/certreq_payload.o $(top_srcdir)/src/charon/vendor_id_payload.o \
$(top_srcdir)/src/charon/proposal_substructure.o $(top_srcdir)/src/charon/payload.o $(top_srcdir)/src/charon/message.o $(top_srcdir)/src/charon/generator.o \
$(top_srcdir)/src/charon/parser.o $(top_srcdir)/src/charon/packet.o $(top_srcdir)/src/charon/socket.o $(top_srcdir)/src/charon/job.o \
$(top_srcdir)/src/charon/delete_child_sa_job.o $(top_srcdir)/src/charon/rekey_child_sa_job.o $(top_srcdir)/src/charon/create_child_sa_requested.o \
$(top_srcdir)/src/charon/delete_established_ike_sa_job.o $(top_srcdir)/src/charon/incoming_packet_job.o $(top_srcdir)/src/charon/delete_half_open_ike_sa_job.o \
$(top_srcdir)/src/charon/retransmit_request_job.o $(top_srcdir)/src/charon/initiate_ike_sa_job.o $(top_srcdir)/src/charon/job_queue.o $(top_srcdir)/src/charon/event_queue.o \
$(top_srcdir)/src/charon/send_queue.o $(top_srcdir)/src/charon/kernel_interface.o $(top_srcdir)/src/charon/thread_pool.o $(top_srcdir)/src/charon/scheduler.o \
$(top_srcdir)/src/charon/sender.o $(top_srcdir)/src/charon/receiver.o $(top_srcdir)/src/charon/stroke_interface.o
