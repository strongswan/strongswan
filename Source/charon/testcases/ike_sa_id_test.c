/**
 * @file ike_sa_id_test.c
 * 
 * @brief Tests to test the IKE_SA Identifier class ike_sa_id_test_t
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
 
#include "ike_sa_id_test.h"

#include "../ike_sa_id.h"

/* 
 * described in Header-File
 */
void test_ike_sa_id(tester_t *tester)
{
	ike_sa_id_t *ike_sa_id, *clone, *equal, *other1, *other2, *other3, *other4;
	spi_t initiator, initiator2, responder, responder2;
	bool is_initiator;
	bool are_equal = FALSE;
	
	initiator = 0;

	initiator2 = 12345612;
	
	responder = 34334;

	responder2 = 987863;
	
	is_initiator = TRUE;
	
	ike_sa_id = ike_sa_id_create(initiator, responder, is_initiator);
	equal = ike_sa_id_create(initiator, responder, is_initiator);
	other1 = ike_sa_id_create(initiator, responder2, is_initiator);
	other2 = ike_sa_id_create(initiator2, responder2, is_initiator);
	other3 = ike_sa_id_create(initiator2, responder, is_initiator);
	is_initiator = FALSE;
	other4 = ike_sa_id_create(initiator, responder, is_initiator);
	
	/* check equality */
	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,equal,&are_equal) == SUCCESS), "equal call check");
	tester->assert_true(tester,(are_equal == TRUE), "equal check");
	tester->assert_true(tester,(equal->equals(equal,ike_sa_id,&are_equal) == SUCCESS), "equal call check");
	tester->assert_true(tester,(are_equal == TRUE), "equal check");	

	/* check clone functionality and equality*/	
	tester->assert_true(tester,(ike_sa_id->clone(ike_sa_id,&clone) == SUCCESS), "clone call check");
	tester->assert_false(tester,(clone == ike_sa_id), "clone pointer check");	
	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,clone,&are_equal) == SUCCESS), "equal call check");
	tester->assert_true(tester,(are_equal == TRUE), "equal check");
	
	/* check for non equality */
	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,other1,&are_equal) == SUCCESS), "equal call check");
	tester->assert_false(tester,(are_equal == TRUE), "equal check");

	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,other2,&are_equal) == SUCCESS), "equal call check");
	tester->assert_false(tester,(are_equal == TRUE), "equal check");

	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,other3,&are_equal) == SUCCESS), "equal call check");
	tester->assert_false(tester,(are_equal == TRUE), "equal check");

	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,other4,&are_equal) == SUCCESS), "equal call check");
	tester->assert_false(tester,(are_equal == TRUE), "equal check");

	tester->assert_true(tester,(other4->replace_values(other4,ike_sa_id) == SUCCESS), "replace values call check");
	tester->assert_true(tester,(ike_sa_id->equals(ike_sa_id,other4,&are_equal) == SUCCESS), "equal call check");
	tester->assert_true(tester,(are_equal == TRUE), "equal check");
	
	
	/* check destroy functionality */
	tester->assert_true(tester,(ike_sa_id->destroy(ike_sa_id) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(equal->destroy(equal) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(clone->destroy(clone) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(other1->destroy(other1) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(other2->destroy(other2) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(other3->destroy(other3) == SUCCESS), "destroy call check");
	tester->assert_true(tester,(other4->destroy(other4) == SUCCESS), "destroy call check");
}
