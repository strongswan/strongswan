/*
 * Copyright (C) 2016 Tobias Brunner
 * HSR Hochschule fuer Technik Rapperswil
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

#include "test_suite.h"

#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/exchange_test_asserts.h>
#include <tests/utils/sa_asserts.h>

/**
 * Regular IKE_SA rekey either initiated by the original initiator or
 * responder of the IKE_SA.
 */
START_TEST(test_regular)
{
	ike_sa_t *a, *b, *new_sa;
	status_t s;

	if (_i)
	{	/* responder rekeys the IKE_SA */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, NULL);
	}
	else
	{	/* initiator rekeys the IKE_SA */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, NULL);
	}
	/* these should never get called as this results in a successful rekeying */
	assert_hook_not_called(ike_updown);
	assert_hook_not_called(child_updown);

	assert_hook_not_called(ike_rekey);
	call_ikesa(a, rekey);
	assert_ike_sa_state(a, IKE_REKEYING);
	assert_hook();

	/* CREATE_CHILD_SA { SA, Ni, KEi } --> */
	assert_hook_rekey(ike_rekey, 1, 3);
	assert_no_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_ike_sa_state(b, IKE_REKEYED);
	assert_child_sa_count(b, 0);
	new_sa = assert_ike_sa_checkout(3, 4, FALSE);
	assert_ike_sa_state(new_sa, IKE_ESTABLISHED);
	assert_child_sa_count(new_sa, 1);
	assert_ike_sa_count(1);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, KEr } */
	assert_hook_rekey(ike_rekey, 1, 3);
	assert_no_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_ike_sa_state(a, IKE_DELETING);
	assert_child_sa_count(a, 0);
	new_sa = assert_ike_sa_checkout(3, 4, TRUE);
	assert_ike_sa_state(new_sa, IKE_ESTABLISHED);
	assert_child_sa_count(new_sa, 1);
	assert_ike_sa_count(2);
	assert_hook();

	/* we don't expect this hook to get called anymore */
	assert_hook_not_called(ike_rekey);

	/* INFORMATIONAL { D } --> */
	assert_single_payload(IN, PLV2_DELETE);
	s = exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	call_ikesa(b, destroy);
	/* <-- INFORMATIONAL { } */
	assert_message_empty(IN);
	s = exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	call_ikesa(a, destroy);

	/* ike_rekey/ike_updown/child_updown */
	assert_hook();
	assert_hook();
	assert_hook();

	charon->ike_sa_manager->flush(charon->ike_sa_manager);
}
END_TEST

Suite *ike_rekey_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ike rekey");

	tc = tcase_create("regular");
	tcase_add_loop_test(tc, test_regular, 0, 2);
	suite_add_tcase(s, tc);

	return s;
}
