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
	proposal_t *prop1, *prop2, *prop3, *prop4, *selected_one;
	linked_list_t *list;
	status_t status;

	prop1 = proposal_create(1);
	prop1->add_algorithm(prop1, IKE, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 20);
	prop1->add_algorithm(prop1, IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop1->add_algorithm(prop1, IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1, 20);
	prop1->add_algorithm(prop1, IKE, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
	
	prop2 = proposal_create(2);
	prop2->add_algorithm(prop2, IKE, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 20);
	prop2->add_algorithm(prop2, IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop2->add_algorithm(prop2, IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 20);
	prop2->add_algorithm(prop2, IKE, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	
	prop3 = proposal_create(3);
	prop3->add_algorithm(prop3, IKE, ENCRYPTION_ALGORITHM, ENCR_DES, 20);
	prop3->add_algorithm(prop3, IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop3->add_algorithm(prop3, IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 20);
	prop3->add_algorithm(prop3, IKE, DIFFIE_HELLMAN_GROUP, MODP_768_BIT, 0);
	
	prop4 = proposal_create(4);
	prop4->add_algorithm(prop4, IKE, ENCRYPTION_ALGORITHM, ENCR_3DES, 20);
	prop4->add_algorithm(prop4, IKE, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop4->add_algorithm(prop4, IKE, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_TIGER, 20);
	prop4->add_algorithm(prop4, IKE, DIFFIE_HELLMAN_GROUP, MODP_768_BIT, 0);
	
	init_config->add_proposal(init_config, prop1);
	init_config->add_proposal(init_config, prop2);
	init_config->add_proposal(init_config, prop3);
	init_config->add_proposal(init_config, prop4);
	
	list = init_config->get_proposals(init_config);
	
	tester->assert_true(tester,(list->get_count(list) == 4), "proposal count check ");

	
	/* going to check proposals */
	/* TODO test?*/
	
	list->destroy(list);
	
	init_config->destroy(init_config);
}
