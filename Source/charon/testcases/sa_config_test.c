/**
 * @file sa_config_test.c
 *
 * @brief Tests for the sa_config_t class.
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

#include "sa_config_test.h"

#include <daemon.h>
#include <config/sa_config.h>
#include <config/traffic_selector.h>
#include <utils/allocator.h>
#include <utils/logger.h>
#include <encoding/payloads/ts_payload.h>


/**
 * Described in header.
 */
void test_sa_config(protected_tester_t *tester)
{
	sa_config_t *sa_config;	
	traffic_selector_t *ts_policy[3], *ts_request[4], *ts_reference[3], **ts_result;
	proposal_t *proposal1, *proposal2, *proposal3, *proposal_sel;
	linked_list_t *proposals_list;
	iterator_t *iterator;
	size_t count;
	logger_t *logger;
	ts_payload_t *ts_payload;
	
	logger = charon->logger_manager->create_logger(charon->logger_manager, TESTER, NULL);
	logger->disable_level(logger, FULL);
	
	sa_config = sa_config_create(ID_IPV4_ADDR, "152.96.193.130", 
								 ID_IPV4_ADDR, "152.96.193.131",
								 RSA_DIGITAL_SIGNATURE,
								 30000);
	
	tester->assert_true(tester, (sa_config != NULL), "sa_config construction");

	
	/* 
	 * test proposal getting and selection 
	 * 
	 */
	
	/* esp only prop */
	proposal1 = proposal_create(1);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	
	/* ah only prop */
	proposal2 = proposal_create(2);
	proposal2->add_algorithm(proposal2, AH, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	
	/* ah and esp prop */
	proposal3 = proposal_create(3);
	proposal3->add_algorithm(proposal3, ESP, ENCRYPTION_ALGORITHM, ENCR_3DES, 16);
	proposal3->add_algorithm(proposal3, AH, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 20);
	
	
	sa_config->add_proposal(sa_config, proposal1);
	sa_config->add_proposal(sa_config, proposal2);
	sa_config->add_proposal(sa_config, proposal3);

	
	proposals_list = sa_config->get_proposals(sa_config);
	tester->assert_true(tester, (proposals_list->get_count(proposals_list) == 3), "proposal count");
	
	
	proposals_list = linked_list_create();
	proposal1 = proposal_create(1);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 32);
	proposal2 = proposal_create(2);
	proposal2->add_algorithm(proposal2, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	proposal2->add_algorithm(proposal2, ESP, ENCRYPTION_ALGORITHM, ENCR_3DES, 16);
	proposal2->add_algorithm(proposal2, ESP, ENCRYPTION_ALGORITHM, ENCR_BLOWFISH, 0);
	proposal2->add_algorithm(proposal2, AH, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	proposal2->add_algorithm(proposal2, AH, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 20);
	
	proposals_list->insert_last(proposals_list, proposal1);
	proposals_list->insert_last(proposals_list, proposal2);
	
	proposal_sel = sa_config->select_proposal(sa_config, proposals_list);
	tester->assert_false(tester, proposal_sel == NULL, "proposal select");
	/* check ESP encryption algo */
	iterator = proposal_sel->create_algorithm_iterator(proposal_sel, ESP, ENCRYPTION_ALGORITHM);
	tester->assert_false(tester, iterator == NULL, "algorithm select ESP");
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		tester->assert_true(tester, algo->algorithm == ENCR_3DES, "ESP encryption algo");
		tester->assert_true(tester, algo->key_size == 16, "ESP encryption keysize");
	}
	iterator->destroy(iterator);
	iterator = proposal_sel->create_algorithm_iterator(proposal_sel, AH, INTEGRITY_ALGORITHM);
	/* check AH integrity algo */
	tester->assert_false(tester, iterator == NULL, "algorithm select AH");
	while (iterator->has_next(iterator))
	{
		algorithm_t *algo;
		iterator->current(iterator, (void**)&algo);
		tester->assert_true(tester, algo->algorithm == AUTH_HMAC_MD5_96, "ESP encryption algo");
		tester->assert_true(tester, algo->key_size == 20, "ESP encryption keysize");
	}
	iterator->destroy(iterator);
	
	proposal_sel->destroy(proposal_sel);

	/* cleanup */
	proposal1->destroy(proposal1);
	proposal1->destroy(proposal2);
	proposals_list->destroy(proposals_list);
	
	/* 
	 * test traffic selection getting and matching 
	 * 
	 */
	
	/* define policies */
	
	/* allow any tcp */
	ts_policy[0] = traffic_selector_create_from_string(6, TS_IPV4_ADDR_RANGE, "0.0.0.0", 0, "255.255.255.255", 65535);
	
	/* allow udp on port 123 to ".122" */
	ts_policy[1] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.122", 123, "152.96.193.122", 123);
	
	/* allow udp on ports > 2000 in subnet ... */
	ts_policy[2] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.0", 2000, "152.96.193.255", 65535);

	

	/* define request and result */
	
	/* udp on subnet:123, should be reduced to ".122"  */
	ts_request[0] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.0", 123, "152.96.193.255", 123);
	ts_reference[0] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.122", 123, "152.96.193.122", 123);
	
	/* should be granted. */
	ts_request[1] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.0", 2000, "152.96.193.255", 2000);
	ts_reference[1] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.0", 2000, "152.96.193.255", 2000);
	
	/* should be reduced to port 2000 - 3000. and range ".193.*" */
	ts_request[2] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.191.0", 1000, "152.96.194.255", 3000);
	ts_reference[2] = traffic_selector_create_from_string(7, TS_IPV4_ADDR_RANGE, "152.96.193.0", 2000, "152.96.193.255", 3000);
	
	/* icmp request, should be discarded */
	ts_request[3] = traffic_selector_create_from_string(1, TS_IPV4_ADDR_RANGE, "0.0.0.0", 0, "255.255.255.255", 65535);
	
	sa_config->add_traffic_selector_initiator(sa_config, ts_policy[0]);
	sa_config->add_traffic_selector_initiator(sa_config, ts_policy[1]);
	sa_config->add_traffic_selector_initiator(sa_config, ts_policy[2]);
	
	count = sa_config->get_traffic_selectors_initiator(sa_config, &ts_result);
	tester->assert_true(tester, (count == 3), "ts get count");
	ts_result[0]->destroy(ts_result[0]);
	ts_result[0]->destroy(ts_result[1]);
	ts_result[0]->destroy(ts_result[2]);
	allocator_free(ts_result);
	
	count = sa_config->select_traffic_selectors_initiator(sa_config, &ts_request[0], 4, &ts_result);
	tester->assert_true(tester, (count == 3), "ts select count");
	
	
	/* store and restore into ts payload, tricky tricky */
	ts_payload = ts_payload_create_from_traffic_selectors(TRUE, ts_result, count);
	
	/* destroy */
	ts_result[0]->destroy(ts_result[0]);
	ts_result[0]->destroy(ts_result[1]); 
	ts_result[0]->destroy(ts_result[2]);
	allocator_free(ts_result);
	
	/* get them again out of the payload */
	count = ts_payload->get_traffic_selectors(ts_payload, &ts_result);
	ts_payload->destroy(ts_payload);
	
	
	
	int i;
	for (i = 0; i<count; i++)
	{
		chunk_t fa_res = ts_result[i]->get_from_address(ts_result[i]);
		chunk_t fa_ref = ts_reference[i]->get_from_address(ts_reference[i]);
		chunk_t ta_res = ts_result[i]->get_to_address(ts_result[i]);
		chunk_t ta_ref = ts_reference[i]->get_to_address(ts_reference[i]);
		u_int16_t fp_res = ts_result[i]->get_from_port(ts_result[i]);
		u_int16_t fp_ref = ts_reference[i]->get_from_port(ts_reference[i]);
		u_int16_t tp_res = ts_result[i]->get_to_port(ts_result[i]);
		u_int16_t tp_ref = ts_reference[i]->get_to_port(ts_reference[i]);

		
		logger->log_chunk(logger, RAW, "from address result", &fa_res);
		logger->log_chunk(logger, RAW, "from address reference", &fa_ref);
		logger->log_chunk(logger, RAW, "to address result", &ta_res);
		logger->log_chunk(logger, RAW, "to address reference", &ta_ref);
		tester->assert_true(tester, fa_res.len == fa_ref.len, "from address len");
		tester->assert_false(tester, memcmp(fa_res.ptr, fa_ref.ptr,fa_res.len), "from address value");
		tester->assert_true(tester, ta_res.len == ta_ref.len, "to address len");
		tester->assert_false(tester, memcmp(ta_res.ptr, ta_ref.ptr,ta_res.len), "to address value");
		
		tester->assert_true(tester, fp_res == fp_ref, "from port");
		tester->assert_true(tester, tp_res == tp_ref, "to port");
		
		allocator_free(fa_res.ptr);
		allocator_free(fa_ref.ptr);
		allocator_free(ta_res.ptr);
		allocator_free(ta_ref.ptr);
	}


	/* destroy */
	ts_result[0]->destroy(ts_result[0]);
	ts_result[0]->destroy(ts_result[1]); 
	ts_result[0]->destroy(ts_result[2]);
	allocator_free(ts_result);	
	
	ts_policy[0]->destroy(ts_policy[0]);
	ts_policy[1]->destroy(ts_policy[1]);
	ts_policy[2]->destroy(ts_policy[2]);
	ts_request[0]->destroy(ts_request[0]);
	ts_reference[0]->destroy(ts_reference[0]);
	ts_request[1]->destroy(ts_request[1]);
	ts_reference[1]->destroy(ts_reference[1]);
	ts_request[2]->destroy(ts_request[2]);
	ts_reference[2]->destroy(ts_reference[2]);
	ts_request[3]->destroy(ts_request[3]);

	sa_config->destroy(sa_config);
}
