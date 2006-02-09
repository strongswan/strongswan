/**
 * @file child_proposal_test.c
 *
 * @brief Tests for the child_proposal_t class.
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

#include "child_proposal_test.h"

#include <daemon.h>
#include <config/child_proposal.h>
#include <utils/allocator.h>
#include <utils/logger.h>


/**
 * Described in header.
 */
void test_child_proposal(protected_tester_t *tester)
{
	child_proposal_t *proposal1, *proposal2, *proposal3;
	iterator_t *iterator;
	algorithm_t *algo;
	bool result;

	proposal1 = child_proposal_create(1);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_3DES, 0);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 32);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	proposal1->add_algorithm(proposal1, ESP, ENCRYPTION_ALGORITHM, ENCR_BLOWFISH, 0);
	proposal1->add_algorithm(proposal1, ESP, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 20);
	proposal1->add_algorithm(proposal1, ESP, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 20);
	proposal1->add_algorithm(proposal1, AH, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	proposal1->add_algorithm(proposal1, AH, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
	
	proposal2 = child_proposal_create(2);
	proposal2->add_algorithm(proposal2, ESP, ENCRYPTION_ALGORITHM, ENCR_3IDEA, 0);
	proposal2->add_algorithm(proposal2, ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	proposal2->add_algorithm(proposal2, ESP, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 20);
	proposal1->add_algorithm(proposal2, AH, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	
	/* ah and esp prop */
	proposal3 = proposal1->select(proposal1, proposal2);
	tester->assert_false(tester, proposal3 == NULL, "proposal select");
	if (proposal3)
	{
		result = proposal3->get_algorithm(proposal3, ESP, ENCRYPTION_ALGORITHM, &algo);
		tester->assert_true(tester, result, "encryption algo select");
		tester->assert_true(tester, algo->algorithm == ENCR_AES_CBC, "encryption algo");
		tester->assert_true(tester, algo->key_size == 16, "encryption keylen");
		
		
		result = proposal3->get_algorithm(proposal3, ESP, INTEGRITY_ALGORITHM, &algo);
		tester->assert_true(tester, result, "integrity algo select");
		tester->assert_true(tester, algo->algorithm == AUTH_HMAC_MD5_96, "integrity algo");
		tester->assert_true(tester, algo->key_size == 20, "integrity keylen");
		
		iterator = proposal3->create_algorithm_iterator(proposal3, ESP, INTEGRITY_ALGORITHM);
		tester->assert_false(tester, iterator == NULL, "integrity algo select");
		while(iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&algo);
			tester->assert_true(tester, algo->algorithm == AUTH_HMAC_MD5_96, "integrity algo");
			tester->assert_true(tester, algo->key_size == 20, "integrity keylen");
		}
		iterator->destroy(iterator);
		
		iterator = proposal3->create_algorithm_iterator(proposal3, AH, DIFFIE_HELLMAN_GROUP );
		tester->assert_false(tester, iterator == NULL, "dh group algo select");
		while(iterator->has_next(iterator))
		{
			iterator->current(iterator, (void**)&algo);
			tester->assert_true(tester, algo->algorithm == MODP_1024_BIT, "dh group algo");
			tester->assert_true(tester, algo->key_size == 0, "dh gorup keylen");
		}
		iterator->destroy(iterator);
		
		proposal3->destroy(proposal3);
	}
	
	proposal1->destroy(proposal1);
	proposal2->destroy(proposal2);
	return;
}
