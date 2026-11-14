/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2026 raghu netrakar
 *
 * Copyright (C) secunet Security Networks AG
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
 * Assert that a redirect works as expected when sent from responder b to
 * initiator a.
 */
static void assert_redirect(ike_sa_t *a, ike_sa_t *b)
{
	identification_t *gateway;
	message_t *msg;
	host_t *dst;

	dst = host_create_from_string("192.0.2.1", 0);
	gateway = identification_create_from_sockaddr(dst->get_sockaddr(dst));
	call_ikesa(b, redirect, gateway);
	gateway->destroy(gateway);
	ck_assert(b->has_condition(b, COND_REDIRECTED));

	/* INFORMATIONAL { N(REDIRECT) } --> */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert(a->has_condition(a, COND_REDIRECTED));

	msg = exchange_test_helper->sender->dequeue(exchange_test_helper->sender);
	ck_assert_int_eq(IKE_SA_INIT, msg->get_exchange_type(msg));
	ck_assert(dst->ip_equals(dst, msg->get_destination(msg)));
	msg->destroy(msg);
	dst->destroy(dst);
}

/**
 * The original responder redirects the original initiator.
 */
START_TEST(test_redirect_initiator)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	assert_ike_sa_count(0);
	assert_redirect(a, b);
	assert_ike_sa_count(1);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Add a REDIRECT notify to the INFORMATIONAL request sent by the initiator,
 * which strongSwan itself never does.
 */
static bool add_redirect(listener_t *listener, ike_sa_t *ike_sa,
						 message_t *message, bool incoming, bool plain)
{
	identification_t *gateway;
	chunk_t data;

	if (plain && !incoming && message->get_request(message) &&
		message->get_exchange_type(message) == INFORMATIONAL)
	{
		gateway = identification_create_from_string("192.0.2.1");
		data = redirect_data_create(gateway, chunk_empty);
		message->add_notify(message, FALSE, REDIRECT, data);
		gateway->destroy(gateway);
		chunk_free(&data);
		return FALSE;
	}
	return TRUE;
}

/**
 * A REDIRECT notify sent by the original initiator is ignored.
 */
START_TEST(test_redirect_responder)
{
	listener_t redirect = {
		.message = add_redirect,
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	/* as a variant, we first rekey the SA from the responder, which makes it
	 * the initiator of the new SA, yet the original roles must be retained */
	if (_i)
	{
		call_ikesa(b, rekey);
		/* CREATE_CHILD_SA { SA, Ni, KEi } --> */
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		/* <-- CREATE_CHILD_SA { SA, Nr, KEr } */
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		/* INFORMATIONAL { D } --> */
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		call_ikesa(a, destroy);
		/* INFORMATIONAL { } --> */
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		call_ikesa(b, destroy);

		/* b is the initiator of the new SA but still the original responder */
		b = assert_ike_sa_checkout(3, 4, TRUE);
		ck_assert(!b->has_condition(b, COND_ORIGINAL_INITIATOR));
		a = assert_ike_sa_checkout(3, 4, FALSE);
		ck_assert(a->has_condition(a, COND_ORIGINAL_INITIATOR));
	}

	exchange_test_helper->add_listener(exchange_test_helper, &redirect);
	call_ikesa(a, send_dpd);

	/* INFORMATIONAL { N(REDIRECT) } --> */
	assert_notify(IN, REDIRECT);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ck_assert(!b->has_condition(b, COND_REDIRECTED));
	assert_ike_sa_count(_i ? 2 : 0);
	/* <-- INFORMATIONAL { } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert(!a->has_condition(a, COND_REDIRECTED));
	assert_ike_sa_state(a, IKE_ESTABLISHED);
	assert_ike_sa_state(b, IKE_ESTABLISHED);
	assert_sa_idle(a);
	assert_sa_idle(b);

	/* a legitimate redirect must still work afterwards */
	assert_redirect(a, b);
	assert_ike_sa_count(_i ? 3 : 1);

	if (!_i)
	{
		call_ikesa(a, destroy);
		call_ikesa(b, destroy);
	}
	charon->ike_sa_manager->flush(charon->ike_sa_manager);
}
END_TEST

Suite *ike_redirect_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ike redirect");

	tc = tcase_create("established");
	tcase_add_test(tc, test_redirect_initiator);
	tcase_add_loop_test(tc, test_redirect_responder, 0, 2);
	suite_add_tcase(s, tc);

	return s;
}
