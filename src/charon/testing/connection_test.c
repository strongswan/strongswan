/**
 * @file connection_test.c
 *
 * @brief Tests for the connection_t class.
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

#include "connection_test.h"

#include <config/connections/connection.h>
#include <crypto/prfs/prf.h>


/**
 * Described in header.
 */
void test_connection(protected_tester_t *tester)
{
	host_t *alice = host_create(AF_INET, "192.168.0.1", 500);
	host_t *bob = host_create(AF_INET, "192.168.0.2", 500);
	connection_t *connection = connection_create("alice-bob", TRUE, alice, bob, RSA_DIGITAL_SIGNATURE);
	proposal_t *prop1, *prop2, *prop3, *prop4;
	linked_list_t *list;

	prop1 = proposal_create(PROTO_IKE);
	prop1->add_algorithm(prop1, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 20);
	prop1->add_algorithm(prop1, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop1->add_algorithm(prop1, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1, 20);
	prop1->add_algorithm(prop1, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
	
	prop2 = proposal_create(PROTO_IKE);
	prop2->add_algorithm(prop2, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 20);
	prop2->add_algorithm(prop2, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop2->add_algorithm(prop2, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 20);
	prop2->add_algorithm(prop2, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	
	prop3 = proposal_create(PROTO_IKE);
	prop3->add_algorithm(prop3, ENCRYPTION_ALGORITHM, ENCR_DES, 20);
	prop3->add_algorithm(prop3, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop3->add_algorithm(prop3, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 20);
	prop3->add_algorithm(prop3, DIFFIE_HELLMAN_GROUP, MODP_768_BIT, 0);
	
	prop4 = proposal_create(PROTO_IKE);
	prop4->add_algorithm(prop4, ENCRYPTION_ALGORITHM, ENCR_3DES, 20);
	prop4->add_algorithm(prop4, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	prop4->add_algorithm(prop4, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_TIGER, 20);
	prop4->add_algorithm(prop4, DIFFIE_HELLMAN_GROUP, MODP_768_BIT, 0);
	
	connection->add_proposal(connection, prop1);
	connection->add_proposal(connection, prop2);
	connection->add_proposal(connection, prop3);
	connection->add_proposal(connection, prop4);
	
	list = connection->get_proposals(connection);
	
	tester->assert_true(tester,(list->get_count(list) == 4), "proposal count check ");

	
	/* going to check proposals */
	/* TODO test?*/
	
	list->destroy(list);
	
	connection->destroy(connection);
}
