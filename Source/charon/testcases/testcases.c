/**
 * @file tests.c
 * 
 * @brief Main for all testcases.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
 
 
#include <stdio.h>

#include <daemon.h>

#include <queues/job_queue.h>
#include <queues/event_queue.h>
#include <queues/send_queue.h>
#include <config/configuration_manager.h>
#include <sa/ike_sa_manager.h>
#include <network/socket.h>
#include <utils/logger_manager.h>
#include <utils/allocator.h>
#include <utils/tester.h>
#include <testcases/linked_list_test.h>
#include <testcases/thread_pool_test.h>
#include <testcases/job_queue_test.h>
#include <testcases/event_queue_test.h>
#include <testcases/send_queue_test.h>
#include <testcases/socket_test.h>
#include <testcases/sender_test.h>
#include <testcases/scheduler_test.h>
#include <testcases/receiver_test.h>
#include <testcases/ike_sa_id_test.h>
#include <testcases/ike_sa_test.h>
#include <testcases/ike_sa_manager_test.h>
#include <testcases/generator_test.h>
#include <testcases/parser_test.h>
#include <testcases/packet_test.h>
#include <testcases/diffie_hellman_test.h>
#include <testcases/hasher_test.h>
#include <testcases/hmac_test.h>
#include <testcases/prf_plus_test.h>
#include <testcases/aes_cbc_crypter_test.h>
#include <testcases/hmac_signer_test.h>
#include <testcases/encryption_payload_test.h>
#include <testcases/init_config_test.h>
#include <testcases/sa_config_test.h>
#include <testcases/rsa_test.h>
#include <testcases/prime_pool_test.h>

/* output for test messages */
extern FILE * stderr;

test_t linked_list_test = {test_linked_list,"Linked List"};
test_t iterator_test = {test_linked_list_iterator,"Linked List Iterator"};
test_t linked_list_insert_and_remove_test = {test_linked_list_insert_and_remove,"Linked List Insert and remove"};
test_t event_queue_test = {test_event_queue,"Event-Queue"};
test_t job_queue_test1 = {test_job_queue,"Job-Queue"};
test_t send_queue_test = {test_send_queue,"Send-Queue"};
test_t socket_test = {test_socket,"Socket"};
test_t thread_pool_test = {test_thread_pool,"Thread Pool"};
test_t sender_test = {test_sender,"Sender"};
test_t scheduler_test = {test_scheduler,"Scheduler"};
test_t receiver_test = {test_receiver,"Receiver"};
test_t ike_sa_id_test = {test_ike_sa_id,"IKE_SA-Identifier"};
test_t ike_sa_test = {test_ike_sa,"IKE_SA"};
test_t ike_sa_manager_test = {test_ike_sa_manager, "IKE_SA-Manager"};
test_t generator_test1 = {test_generator_with_header_payload,"Generator: header payload"};
test_t generator_test2 = {test_generator_with_transform_attribute,"Generator: transform attribute"};
test_t generator_test3 = {test_generator_with_transform_substructure,"Generator: transform substructure"};
test_t generator_test4 = {test_generator_with_proposal_substructure,"Generator: proposal substructure"};
test_t generator_test5 = {test_generator_with_sa_payload,"Generator: Message with SA Payload"};
test_t generator_test6 = {test_generator_with_ke_payload,"Generator: KE Payload"};
test_t generator_test7 = {test_generator_with_notify_payload,"Generator: Notify Payload"};
test_t generator_test8 = {test_generator_with_nonce_payload,"Generator: Nonce Payload"};
test_t generator_test9 = {test_generator_with_id_payload,"Generator: ID Payload"};
test_t generator_test10 = {test_generator_with_auth_payload,"Generator: AUTH Payload"};
test_t generator_test11 = {test_generator_with_ts_payload,"Generator: TS Payload"};
test_t generator_test12 = {test_generator_with_cert_payload,"Generator: CERT Payload"};
test_t generator_test13 = {test_generator_with_certreq_payload,"Generator: CERTREQ Payload"};
test_t parser_test1 = {test_parser_with_header_payload, "Parser: header payload"};
test_t parser_test2 = {test_parser_with_sa_payload, "Parser: sa payload"};
test_t parser_test3 = {test_parser_with_nonce_payload, "Parser: nonce payload"};
test_t parser_test4 = {test_parser_with_ke_payload, "Parser: key exchange payload"};
test_t parser_test5 = {test_parser_with_notify_payload, "Parser: notify payload"};
test_t parser_test6 = {test_parser_with_id_payload, "Parser: ID payload"};
test_t parser_test7 = {test_parser_with_auth_payload, "Parser: AUTH payload"};
test_t parser_test8 = {test_parser_with_ts_payload, "Parser: TS payload"};
test_t parser_test9 = {test_parser_with_cert_payload, "Parser: CERT payload"};
test_t parser_test10 = {test_parser_with_certreq_payload, "Parser: CERTREQ payload"};
test_t packet_test = {test_packet,"Packet"};
test_t diffie_hellman_test = {test_diffie_hellman,"Diffie Hellman"};
test_t sha1_hasher_test = {test_sha1_hasher,"SHA1 hasher"};
test_t md5_hasher_test = {test_md5_hasher,"MD5 hasher"};
test_t hmac_test1 = {test_hmac_sha1, "HMAC using SHA1"};
test_t hmac_test2 = {test_hmac_md5, "HMAC using MD5"};
test_t prf_plus_test = {test_prf_plus, "prf+"};
test_t aes_cbc_crypter_test = {test_aes_cbc_crypter, "AES CBC"};
test_t hmac_signer_test1 = {test_hmac_md5_signer, "HMAC MD5 signer test"};
test_t hmac_signer_test2 = {test_hmac_sha1_signer, "HMAC SHA1 signer test"};
test_t encryption_payload_test = {test_encryption_payload, "encryption payload test"};
test_t init_config_test = {test_init_config, "init_config_t test"};
test_t sa_config_test = {test_sa_config, "sa_config_t test"};
test_t rsa_test = {test_rsa, "RSA private/public key test"};
test_t prime_pool_test = {test_prime_pool, "Prime pool"};


daemon_t* charon;

static void daemon_kill(daemon_t *this, char* none)
{
	this->logger_manager->destroy(this->logger_manager);
	this->socket->destroy(this->socket);
	this->ike_sa_manager->destroy(this->ike_sa_manager);
	this->job_queue->destroy(this->job_queue);
	this->prime_pool->destroy(this->prime_pool);
	this->event_queue->destroy(this->event_queue);
	this->send_queue->destroy(this->send_queue);
	this->configuration_manager->destroy(this->configuration_manager);
	allocator_free(charon);
}

/**
 * @brief Create the dummy daemon for testing.
 * 
 * @return 	created daemon_t
 */
daemon_t *daemon_create()
{	
	charon = allocator_alloc_thing(daemon_t);
		
	/* assign methods */
	charon->kill = daemon_kill;
	
	charon->logger_manager = logger_manager_create(0);
	charon->socket = socket_create(4600);
	charon->ike_sa_manager = ike_sa_manager_create();
	charon->job_queue = job_queue_create();
	charon->event_queue = event_queue_create();
	charon->send_queue = send_queue_create();
	charon->prime_pool = prime_pool_create(0);
	charon->configuration_manager = configuration_manager_create(RETRANSMIT_TIMEOUT,MAX_RETRANSMIT_COUNT);
	charon->sender = NULL;
	charon->receiver = NULL;
	charon->scheduler = NULL;
	charon->thread_pool = NULL;
	
	return charon;
}


int main()
{
	FILE * test_output = stderr;
	
	test_t *all_tests[] ={
		&linked_list_test,
		&iterator_test,
		&linked_list_insert_and_remove_test,
		&thread_pool_test,
		&job_queue_test1,
		&event_queue_test,
		&send_queue_test,
		&scheduler_test,
		&socket_test,
		&sender_test,
		&receiver_test,
		&ike_sa_id_test,
		&ike_sa_test,
		&generator_test1,
		&generator_test2,
		&parser_test1,
		&parser_test2,
		&parser_test3,
		&parser_test4,
		&parser_test5,
		&parser_test6,
		&parser_test7,
		&parser_test8,
		&parser_test9,
		&parser_test10,
		&generator_test3,
		&generator_test4,
		&generator_test5,
		&generator_test6,
		&generator_test7,
		&generator_test8,
		&generator_test9,
		&generator_test10,
		&generator_test11,
		&generator_test12,
		&generator_test13,
		&ike_sa_manager_test,
		&packet_test,
		&diffie_hellman_test,
		&sha1_hasher_test,
		&md5_hasher_test,
		&hmac_test1,
		&hmac_test2,
		&prf_plus_test,
		&aes_cbc_crypter_test,
		&hmac_signer_test1,
		&hmac_signer_test2,
		&encryption_payload_test,
		&init_config_test,
		&sa_config_test,
		&rsa_test,
		&prime_pool_test,
		NULL
	};
	
	/* allocator needs initialization */
	allocator_init();
 
	daemon_create();
 
	charon->logger_manager->disable_logger_level(charon->logger_manager,TESTER,FULL);
//	charon->logger_manager->enable_logger_level(charon->logger_manager,TESTER,RAW);
	
	tester_t *tester = tester_create(test_output, FALSE);
	

	tester->perform_tests(tester,all_tests);
//	tester->perform_test(tester,&generator_test13); 
	
	
	tester->destroy(tester);
	
	charon->kill(charon, NULL);
	
#ifdef LEAK_DETECTIVE
	/* Leaks are reported on stderr */
	report_memory_leaks(void);
#endif
	
	return 0;
}
