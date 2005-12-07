/**
 * @file init_config_test.c
 *
 * @brief Tests for the init_config_t class.
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

#include "init_config_test.h"

#include <config/init_config.h>
#include <utils/allocator.h>


/**
 * Described in header.
 */
void test_init_config(protected_tester_t *tester)
{
	init_config_t *init_config = init_config_create("192.168.0.1","192.168.0.2",500,500);
	ike_proposal_t prop1, prop2, prop3, prop4, selected_one;
	ike_proposal_t *proposal_list;
	size_t proposal_count;
	status_t status;

	prop1.encryption_algorithm = ENCR_AES_CBC;
	prop1.encryption_algorithm_key_length = 20;
	prop1.integrity_algorithm = AUTH_HMAC_SHA1_96;
	prop1.integrity_algorithm_key_length = 20;
	prop1.pseudo_random_function = PRF_HMAC_SHA1;
	prop1.pseudo_random_function_key_length = 20;
	prop1.diffie_hellman_group = MODP_2048_BIT;
	
	prop2 = prop1;
	prop2.pseudo_random_function = PRF_HMAC_MD5;
	prop2.diffie_hellman_group = MODP_1024_BIT;
	
	prop3 = prop1;
	prop3.encryption_algorithm = ENCR_DES;
	prop3.diffie_hellman_group = MODP_768_BIT;
	
	prop4 = prop1;
	
	prop4.encryption_algorithm = ENCR_3DES;
	prop4.pseudo_random_function = PRF_HMAC_TIGER;
	
	init_config->add_proposal(init_config,1,prop1);
	init_config->add_proposal(init_config,1,prop2);
	init_config->add_proposal(init_config,3,prop3);
	init_config->add_proposal(init_config,2,prop4);
	
	proposal_count = init_config->get_proposals(init_config,&proposal_list);
	
	tester->assert_true(tester,(proposal_count == 4), "proposal count check ");
	
	tester->assert_true(tester,(proposal_list[0].encryption_algorithm == ENCR_AES_CBC), "encryption algorithm check 1");
	tester->assert_true(tester,(proposal_list[0].pseudo_random_function == PRF_HMAC_MD5), "prf check 1");

	tester->assert_true(tester,(proposal_list[1].encryption_algorithm == ENCR_3DES), "encryption algorithm check 2");
	tester->assert_true(tester,(proposal_list[1].pseudo_random_function == PRF_HMAC_TIGER), "prf check 2");
	
	tester->assert_true(tester,(proposal_list[2].encryption_algorithm == ENCR_AES_CBC), "encryption algorithm check 3");
	tester->assert_true(tester,(proposal_list[2].pseudo_random_function == PRF_HMAC_SHA1), "prf check 3");

	tester->assert_true(tester,(proposal_list[3].encryption_algorithm == ENCR_DES), "encryption algorithm check 4");
	tester->assert_true(tester,(proposal_list[3].pseudo_random_function == PRF_HMAC_SHA1), "prf check 4");
	
	
	
	/* going to check proposals */
	status = init_config->select_proposal(init_config,proposal_list,proposal_count,&selected_one);
	tester->assert_true(tester,(status == SUCCESS), "select proposal call check 1");

	tester->assert_true(tester,(selected_one.encryption_algorithm == ENCR_AES_CBC), "encryption algorithm check");
	tester->assert_true(tester,(selected_one.pseudo_random_function == PRF_HMAC_MD5), "prf check");

	proposal_list[0].encryption_algorithm = ENCR_DES_IV32;	
	
	status = init_config->select_proposal(init_config,proposal_list,proposal_count,&selected_one);
	tester->assert_true(tester,(status == SUCCESS), "select proposal call check 2");

	tester->assert_true(tester,(selected_one.encryption_algorithm == ENCR_3DES), "encryption algorithm check");
	tester->assert_true(tester,(selected_one.pseudo_random_function == PRF_HMAC_TIGER), "prf check");

	proposal_list[1].pseudo_random_function = PRF_AES128_CBC;
	
	status = init_config->select_proposal(init_config,proposal_list,proposal_count,&selected_one);
	tester->assert_true(tester,(status == SUCCESS), "select proposal call check 3");

	tester->assert_true(tester,(selected_one.encryption_algorithm == ENCR_AES_CBC), "encryption algorithm check");
	tester->assert_true(tester,(selected_one.pseudo_random_function == PRF_HMAC_SHA1), "prf check");

	proposal_list[2].pseudo_random_function = PRF_AES128_CBC;
	
	status = init_config->select_proposal(init_config,proposal_list,proposal_count,&selected_one);
	tester->assert_true(tester,(status == SUCCESS), "select proposal call check 4");

	tester->assert_true(tester,(selected_one.encryption_algorithm == ENCR_DES), "encryption algorithm check");
	tester->assert_true(tester,(selected_one.pseudo_random_function == PRF_HMAC_SHA1), "prf check");

	proposal_list[3].pseudo_random_function = PRF_AES128_CBC;
	
	status = init_config->select_proposal(init_config,proposal_list,proposal_count,&selected_one);
	tester->assert_true(tester,(status == NOT_FOUND), "select proposal call check 5");

	tester->assert_true(tester,(init_config->get_dh_group_number(init_config,1) == MODP_1024_BIT), "get DH group number call check 1");
	tester->assert_true(tester,(init_config->get_dh_group_number(init_config,2) == MODP_2048_BIT), "get DH group number call check 2");
	tester->assert_true(tester,(init_config->get_dh_group_number(init_config,3) == MODP_2048_BIT), "get DH group number call check 3");
	tester->assert_true(tester,(init_config->get_dh_group_number(init_config,4) == MODP_768_BIT), "get DH group number call check 4");	
	
	allocator_free(proposal_list);
	
	init_config->destroy(init_config);
}
