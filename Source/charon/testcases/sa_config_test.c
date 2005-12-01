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


/**
 * Described in header.
 */
void test_sa_config(tester_t *tester)
{
	sa_config_t *sa_config;	
	traffic_selector_t *ts_policy[3], *ts_request[4], *ts_reference[3], **ts_result;
	child_proposal_t prop[3], *prop_result;
	size_t count;
	logger_t *logger;
	
	u_int8_t spi[4] = {0x01,0x02,0x03,0x04};
	
	logger = charon->logger_manager->create_logger(charon->logger_manager, TESTER, NULL);
	logger->disable_level(logger, FULL);
	
	sa_config = sa_config_create(ID_IPV4_ADDR, "152.96.193.130", 
								 ID_IPV4_ADDR, "152.96.193.131",
								 RSA_DIGITAL_SIGNATURE);
	
	tester->assert_true(tester, (sa_config != NULL), "sa_config construction");

	
	/* 
	 * test proposal getting and selection 
	 * 
	 */
	
	/* esp only prop */
	prop[0].ah.is_set = FALSE;
	prop[0].esp.is_set = TRUE;
	prop[0].esp.encryption_algorithm = ENCR_AES_CBC;
	prop[0].esp.encryption_algorithm_key_size = 16;
	
	/* ah only prop */
	prop[1].esp.is_set = FALSE;
	prop[1].ah.is_set = TRUE;
	prop[1].ah.integrity_algorithm = AUTH_HMAC_SHA1_96;
	prop[1].ah.integrity_algorithm_key_size = 20;
	
	/* ah and esp prop */
	prop[2].esp.is_set = TRUE;
	prop[2].esp.encryption_algorithm = ENCR_3DES;
	prop[2].esp.encryption_algorithm_key_size = 16;
	prop[2].ah.is_set = TRUE;
	prop[2].ah.integrity_algorithm = AUTH_HMAC_MD5_96;
	prop[2].ah.integrity_algorithm_key_size = 20;
	
	
	sa_config->add_proposal(sa_config, &prop[0]);
	sa_config->add_proposal(sa_config, &prop[1]);
	sa_config->add_proposal(sa_config, &prop[2]);

	
	count = sa_config->get_proposals(sa_config, spi, spi, &prop_result);
	tester->assert_true(tester, (count == 3), "proposal count");
	allocator_free(prop_result);
	
	
		
	prop_result = sa_config->select_proposal(sa_config, spi, spi, &prop[1], 2);
	tester->assert_true(tester, prop_result->esp.is_set == prop[1].esp.is_set, "esp.is_set");
	tester->assert_true(tester, prop_result->ah.integrity_algorithm == prop[1].ah.integrity_algorithm, "ah.integrity_algorithm");
	tester->assert_true(tester, prop_result->ah.integrity_algorithm_key_size == prop[1].ah.integrity_algorithm_key_size, "ah.integrity_algorithm_key_size");
	tester->assert_true(tester, memcmp(prop_result->ah.spi, spi, 4) == 0, "spi");
	allocator_free(prop_result);

	
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
	
	sa_config->add_traffic_selector(sa_config, ts_policy[0]);
	sa_config->add_traffic_selector(sa_config, ts_policy[1]);
	sa_config->add_traffic_selector(sa_config, ts_policy[2]);
	
	count = sa_config->get_traffic_selectors(sa_config, &ts_result);
	tester->assert_true(tester, (count == 3), "ts get count");
	ts_result[0]->destroy(ts_result[0]);
	ts_result[0]->destroy(ts_result[1]);
	ts_result[0]->destroy(ts_result[2]);
	allocator_free(ts_result);
	
	count = sa_config->select_traffic_selectors(sa_config, &ts_request[0], 4, &ts_result);
	tester->assert_true(tester, (count == 3), "ts select count");
	
	
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
