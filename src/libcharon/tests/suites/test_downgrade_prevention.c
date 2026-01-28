/*
 * Copyright (C) 2025
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
 * Regular IKE_SA establishment with both peers supporting full transcript auth.
 * Both peers should negotiate the extension and establish the SA successfully.
 */
START_TEST(test_both_support)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072",
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	/* Ensure full transcript auth is enabled (in case a previous test disabled it) */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> (register listener BEFORE initiate to catch outgoing msg) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* Responder processes request and sends response with notify */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	/* <-- IKE_SA_INIT (initiator receives response) */
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	/* Verify both peers have the extension enabled */
	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	assert_child_sa_count(a, 1);
	assert_child_sa_count(b, 1);

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Test using establish_sa helper - verifies extension works with standard
 * SA establishment flow.
 */
START_TEST(test_establish_sa)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper, &a, &b, NULL);

	/* Verify both peers have the extension enabled after SA establishment */
	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	assert_child_sa_count(a, 1);
	assert_child_sa_count(b, 1);

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Initiator doesn't support full transcript auth, responder does.
 * SA should be established successfully without the extension.
 */
START_TEST(test_initiator_no_support)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072",
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	/* Disable full transcript auth - affects initiator task creation */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> (register listener BEFORE initiate to catch outgoing msg) */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* Re-enable for responder before it processes the message */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	/* Responder processes request and sends notify (always sends if supported,
	 * regardless of whether initiator sent it - prevents stripping attacks) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	/* <-- IKE_SA_INIT (initiator receives response with notify) */
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	/* Verify extension is NOT enabled on either peer */
	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	assert_child_sa_count(a, 1);
	assert_child_sa_count(b, 1);

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Initiator supports full transcript auth, responder doesn't.
 * SA should be established successfully without the extension.
 */
START_TEST(test_responder_no_support)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072",
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	/* Ensure full transcript auth is enabled for initiator */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> (register listener BEFORE initiate to catch outgoing msg) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* Disable full transcript auth for responder before it processes
	 * and creates its ike_init task */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	/* Responder processes request but doesn't echo notify (disabled) */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	/* <-- IKE_SA_INIT (initiator receives response without notify) */
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));

	/* Re-enable for rest of test */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	/* Verify extension is NOT enabled on either peer (responder didn't echo) */
	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	assert_child_sa_count(a, 1);
	assert_child_sa_count(b, 1);

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Neither peer supports full transcript auth.
 * SA should be established successfully without the extension.
 */
START_TEST(test_neither_support)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072",
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	/* Disable full transcript auth for both peers */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> (register listener BEFORE initiate to catch outgoing msg) */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* Responder processes request but doesn't send notify (disabled) */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	/* <-- IKE_SA_INIT (initiator receives response) */
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	/* Verify extension is NOT enabled on either peer */
	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	assert_child_sa_count(a, 1);
	assert_child_sa_count(b, 1);

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);

	/* Re-enable for other tests */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);
}
END_TEST

Suite *downgrade_prevention_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("downgrade prevention");

	tc = tcase_create("negotiation");
	tcase_add_test(tc, test_responder_no_support);
	tcase_add_test(tc, test_both_support);
	tcase_add_test(tc, test_establish_sa);
	tcase_add_test(tc, test_initiator_no_support);
	tcase_add_test(tc, test_neither_support);
	suite_add_tcase(s, tc);

	return s;
}
