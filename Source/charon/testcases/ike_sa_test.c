/**
 * @file ike_sa_test.c
 * 
 * @brief Tests to test the IKE_SA type ike_sa_t
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

#include "ike_sa_test.h"

#include "../types.h"
#include "../message.h"
#include "../configuration.h"
#include "../ike_sa.h"

void test_ike_sa(tester_t *tester)
{
	ike_sa_t *ike_sa;
	ike_sa_id_t *ike_sa_id;
	spi_t initiator, responder;
	bool is_initiator;
	

	initiator = 0;
	responder = 34334LL;
	is_initiator = TRUE;
	/* create a ike_sa_id object for the new IKE_SA */
	ike_sa_id = ike_sa_id_create(initiator, responder, is_initiator);
	
	/* empty message and configuration objects are created */
	
	
	/* test every ike_sa function */
	ike_sa = ike_sa_create(ike_sa_id);
	
	ike_sa->initialize_connection(ike_sa, NULL);
	
	tester->assert_true(tester,(ike_sa != NULL), "ike_sa pointer check");

	tester->assert_true(tester,(ike_sa->destroy(ike_sa) == SUCCESS), "destroy call check");
	
	ike_sa_id->destroy(ike_sa_id);
}
