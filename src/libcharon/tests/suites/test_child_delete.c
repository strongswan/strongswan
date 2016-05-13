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

#include <daemon.h>
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/exchange_test_asserts.h>
#include <tests/utils/sa_asserts.h>

/**
 * Regular CHILD_SA deletion either initiated by the original initiator or
 * responder of the IKE_SA.
 */
START_TEST(test_regular)
{
	ike_sa_t *a, *b;

	if (_i)
	{	/* responder deletes the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a);
	}
	else
	{	/* initiator deletes the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b);
	}
	assert_hook_not_called(child_updown);
	call_ikesa(a, delete_child_sa, PROTO_ESP, _i+1, FALSE);
	assert_child_sa_state(a, _i+1, CHILD_DELETING);
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_updown(child_updown, FALSE);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 0);
	assert_hook();

	/* <-- INFORMATIONAL { D } */
	assert_hook_updown(child_updown, FALSE);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 0);
	assert_hook();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Both peers initiate the CHILD_SA deletion concurrently and should handle
 * the collision properly.
 */
START_TEST(test_collision)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b);
	/* both peers delete the CHILD_SA concurrently */
	assert_hook_not_called(child_updown);
	call_ikesa(a, delete_child_sa, PROTO_ESP, 1, FALSE);
	assert_child_sa_state(a, 1, CHILD_DELETING);
	call_ikesa(b, delete_child_sa, PROTO_ESP, 2, FALSE);
	assert_child_sa_state(b, 2, CHILD_DELETING);
	assert_hook();

	/* RFC 7296 says:
	 *
	 *   Normally, the response in the INFORMATIONAL exchange will contain
	 *   Delete payloads for the paired SAs going in the other direction.
	 *   There is one exception.  If, by chance, both ends of a set of SAs
	 *   independently decide to close them, each may send a Delete payload
	 *   and the two requests may cross in the network.  If a node receives a
	 *   delete request for SAs for which it has already issued a delete
	 *   request, it MUST delete the outgoing SAs while processing the request
	 *   and the incoming SAs while processing the response.  In that case,
	 *   the responses MUST NOT include Delete payloads for the deleted SAs,
	 *   since that would result in duplicate deletion and could in theory
	 *   delete the wrong SA.
	 *
	 * We don't handle SAs separately so we expect both are still installed,
	 * but the INFORMATIONAL response should not contain a DELETE payload.
	 */

	/* INFORMATIONAL { D } --> */
	assert_hook_not_called(child_updown);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 2, CHILD_DELETING);
	/* <-- INFORMATIONAL { D } */
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 1, CHILD_DELETING);
	assert_hook();

	/* <-- INFORMATIONAL { } */
	assert_hook_updown(child_updown, FALSE);
	assert_message_empty(IN);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 0);
	assert_hook();
	/* INFORMATIONAL { } --> */
	assert_hook_updown(child_updown, FALSE);
	assert_message_empty(IN);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 0);
	assert_hook();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

Suite *child_delete_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("child delete");

	tc = tcase_create("regular");
	tcase_add_loop_test(tc, test_regular, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("collision");
	tcase_add_test(tc, test_collision);
	suite_add_tcase(s, tc);

	return s;
}
