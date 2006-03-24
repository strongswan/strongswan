/**
 * @file child_sa_test.c
 *
 * @brief Tests for the child_sa_t class.
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

#include "child_sa_test.h"

#include <daemon.h>
#include <sa/child_sa.h>
#include <utils/allocator.h>
#include <utils/logger.h>


/**
 * Described in header.
 */
void test_child_sa(protected_tester_t *tester)
{
	proposal_t *proposal1, *proposal2;
	linked_list_t *list;
	host_t *local_me, *remote_me;
	host_t *local_other, *remote_other;
	child_sa_t *local_sa, *remote_sa;
	prf_plus_t *local_prf_plus, *remote_prf_plus;
	prf_t *local_prf, *remote_prf;
	u_int8_t key_buffer[] = {0x01,0x02,0x03,0x04};
	chunk_t key = {key_buffer, sizeof(key_buffer)};
	status_t status;
	
	/* setup test data */
	local_me = host_create(AF_INET, "192.168.0.1", 0);
	local_other = host_create(AF_INET, "192.168.0.2", 0);
	remote_me = host_create(AF_INET, "192.168.0.3", 0);
	remote_other = host_create(AF_INET, "192.168.0.4", 0);
	
	local_sa = child_sa_create(local_me, local_other);
	remote_sa = child_sa_create(remote_me, remote_other);
	
	proposal1 = proposal_create(1);
	proposal1->add_algorithm(proposal1, PROTO_ESP, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	
	proposal2 = proposal_create(2);
	proposal2->add_algorithm(proposal2, PROTO_AH, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
	
	list = linked_list_create();
	list->insert_last(list, proposal1);
	list->insert_last(list, proposal2);
	
	local_prf = prf_create(PRF_HMAC_SHA1);
	remote_prf = prf_create(PRF_HMAC_SHA1);
	local_prf->set_key(local_prf, key);
	remote_prf->set_key(remote_prf, key);
	local_prf_plus = prf_plus_create(local_prf, key);
	remote_prf_plus = prf_plus_create(remote_prf, key);
	
	/* 
	 * local plays initiator 
	 ***********************
	*/
	status = local_sa->alloc(local_sa, list);
	tester->assert_true(tester, status == SUCCESS, "spi allocation");
	
	status = remote_sa->add(remote_sa, proposal1, remote_prf_plus);
	tester->assert_true(tester, status == SUCCESS, "sa add");
	
	status = local_sa->update(local_sa, proposal1, local_prf_plus);
	tester->assert_true(tester, status == SUCCESS, "sa update");
	
	/* cleanup */
	proposal1->destroy(proposal1);
	proposal2->destroy(proposal2);
	list->destroy(list);
	local_prf->destroy(local_prf);
	local_prf_plus->destroy(local_prf_plus);
	remote_prf->destroy(remote_prf);
	remote_prf_plus->destroy(remote_prf_plus);
	local_sa->destroy(local_sa);
	remote_sa->destroy(remote_sa);
	local_me->destroy(local_me);
	local_other->destroy(local_other);
	remote_me->destroy(remote_me);
	remote_other->destroy(remote_other);
	
	
}
