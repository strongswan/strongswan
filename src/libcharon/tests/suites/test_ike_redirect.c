/*
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

#include <daemon.h>
#include <sa/redirect_manager.h>
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/sa_asserts.h>

/**
 * Add a REDIRECT notify to the INFORMATIONAL request sent by the initiator,
 * which strongSwan itself never does
 */
static bool add_redirect(listener_t *listener, ike_sa_t *ike_sa,
						 message_t *message, bool incoming, bool plain)
{
	identification_t *gateway;
	chunk_t data;

	if (plain && !incoming && message->get_request(message) &&
		message->get_exchange_type(message) == INFORMATIONAL &&
		streq("init", ike_sa->get_name(ike_sa)))
	{
		gateway = identification_create_from_string("192.0.2.1");
		data = redirect_data_create(gateway, chunk_empty);
		message->add_notify(message, FALSE, REDIRECT, data);
		gateway->destroy(gateway);
		chunk_free(&data);
	}
	return TRUE;
}

/**
 * The original responder redirects the original initiator
 */
START_TEST(test_redirect_responder)
{
	identification_t *gateway;
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	gateway = identification_create_from_string("192.0.2.1");
	call_ikesa(b, redirect, gateway);
	gateway->destroy(gateway);
	ck_assert(b->has_condition(b, COND_REDIRECTED));

	/* INFORMATIONAL { N(REDIRECT) } --> */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert(a->has_condition(a, COND_REDIRECTED));
	assert_ike_sa_count(1);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * A REDIRECT sent by the original initiator is ignored
 */
START_TEST(test_redirect_initiator)
{
	listener_t redirect = {
		.message = add_redirect,
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	exchange_test_helper->add_listener(exchange_test_helper, &redirect);
	call_ikesa(a, send_dpd);
	/* INFORMATIONAL { N(REDIRECT) } --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	charon->bus->remove_listener(charon->bus, &redirect);
	ck_assert(!b->has_condition(b, COND_REDIRECTED));
	assert_ike_sa_count(0);
	/* <-- INFORMATIONAL { } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert(!a->has_condition(a, COND_REDIRECTED));
	assert_ike_sa_state(a, IKE_ESTABLISHED);
	assert_ike_sa_state(b, IKE_ESTABLISHED);
	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

Suite *ike_redirect_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ike redirect");

	tc = tcase_create("established");
	tcase_add_test(tc, test_redirect_responder);
	tcase_add_test(tc, test_redirect_initiator);
	suite_add_tcase(s, tc);

	return s;
}
