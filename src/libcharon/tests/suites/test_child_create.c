/*
 * Copyright (C) 2016-2026 Tobias Brunner
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
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/exchange_test_asserts.h>
#include <tests/utils/job_asserts.h>
#include <tests/utils/sa_asserts.h>

#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/sa_payload.h>

/**
 * Convert the IKE_AUTH request to a minimal CREATE_CHILD_SA request
 */
static bool fake_create_child_sa(listener_t *listener, ike_sa_t *ike_sa,
								 message_t *message, bool incoming, bool plain)
{
	if (plain && !incoming &&
		message->get_exchange_type(message) == IKE_AUTH &&
		message->get_request(message))
	{
		enumerator_t *enumerator = message->create_payload_enumerator(message);
		nonce_payload_t *nonce;
		sa_payload_t *sa;
		payload_t *pld;

		while (enumerator->enumerate(enumerator, &pld))
		{
			message->remove_payload_at(message, enumerator);
			pld->destroy(pld);
		}
		enumerator->destroy(enumerator);

		/* an SA and a nonce payload are necessary to pass exchange rules */
		message->set_exchange_type(message, CREATE_CHILD_SA);
		sa = sa_payload_create(PLV2_SECURITY_ASSOCIATION);
		message->add_payload(message, (payload_t*)sa);
		nonce = nonce_payload_create(PLV2_NONCE);
		nonce->set_nonce(nonce, chunk_from_chars(0x00,0x00,0x00,0x00,0x00,0x00,
												 0x00,0x00,0x00,0x00,0x00,0x00,
												 0x00,0x00,0x00,0x00));
		message->add_payload(message, (payload_t*)nonce);
		free(listener);
		return FALSE;
	}
	return TRUE;
}

#define send_fake_create_child_sa() ({ \
	listener_t *_msg_listener; \
	INIT(_msg_listener, \
		.message = fake_create_child_sa, \
	); \
	exchange_test_helper->add_listener(exchange_test_helper, _msg_listener); \
})

typedef struct proposal_mismatch_listener_t proposal_mismatch_listener_t;

/** Listener that records the provenance of proposal mismatch alerts. */
struct proposal_mismatch_listener_t {
	listener_t listener;
	alert_t expected;
	u_int received, configured;
	u_int received_proposals, configured_proposals;
};

static bool proposal_mismatch_alert(listener_t *listener, ike_sa_t *ike_sa,
								alert_t alert, va_list args)
{
	proposal_mismatch_listener_t *this =
		(proposal_mismatch_listener_t*)listener;
	linked_list_t *proposals;
	bool received;

	if (alert != this->expected)
	{
		return TRUE;
	}

	received = va_arg(args, int);
	proposals = va_arg(args, linked_list_t*);
	if (received)
	{
		this->received++;
		this->received_proposals = proposals->get_count(proposals);
	}
	else
	{
		this->configured++;
		this->configured_proposals = proposals->get_count(proposals);
	}
	return TRUE;
}

/**
 * This ensures we don't accept a CREATE_CHILD_SA request before the IKE SA is
 * established.
 */
START_TEST(test_pre_establish)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.eap = TRUE,
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;
	message_t *msg;
	status_t s;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	call_ikesa(a, initiate, child_cfg, NULL);

	/* IKE_SA_INIT --> */
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* <-- IKE_SA_INIT */
	assert_notify(IN, CHILDLESS_IKEV2_SUPPORTED);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_payload(IN, PLV2_SECURITY_ASSOCIATION);
	assert_payload(IN, PLV2_TS_INITIATOR);
	assert_payload(IN, PLV2_TS_RESPONDER);
	assert_no_payload(IN, PLV2_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	if (_i == 0)
	{	/* test the regular case with EAP authentication */
		/* <-- IKE_AUTH */
		assert_payload(IN, PLV2_EAP);
		assert_payload(IN, PLV2_AUTH);
		assert_no_payload(IN, PLV2_SECURITY_ASSOCIATION);
		assert_no_payload(IN, PLV2_TS_INITIATOR);
		assert_no_payload(IN, PLV2_TS_RESPONDER);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);

		/* IKE_AUTH --> */
		assert_single_payload(IN, PLV2_EAP);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);

		/* <-- IKE_AUTH */
		assert_single_payload(IN, PLV2_EAP);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);

		/* IKE_AUTH --> */
		assert_single_payload(IN, PLV2_AUTH);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		assert_child_sa_count(b, 1);
		assert_ipsec_sas_installed(b, 1, 2);

		/* <-- IKE_AUTH */
		assert_payload(IN, PLV2_SECURITY_ASSOCIATION);
		assert_payload(IN, PLV2_TS_INITIATOR);
		assert_payload(IN, PLV2_TS_RESPONDER);
		assert_payload(IN, PLV2_AUTH);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		assert_child_sa_count(a, 1);
		assert_ipsec_sas_installed(a, 1, 2);

		assert_sa_idle(a);
		assert_sa_idle(b);
	}
	else
	{	/* after processing the IKE_AUTH response, we modify the next request to
		 * simulate an attacker that sends a CREATE_CHILD_SA request for the
		 * incomplete IKE SA */
		send_fake_create_child_sa();
		/* <-- IKE_AUTH */
		assert_payload(IN, PLV2_EAP);
		assert_payload(IN, PLV2_AUTH);
		assert_no_payload(IN, PLV2_SECURITY_ASSOCIATION);
		assert_no_payload(IN, PLV2_TS_INITIATOR);
		assert_no_payload(IN, PLV2_TS_RESPONDER);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);

		/* CREATE_CHILD_SA --> must be rejected without a response */
		s = exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		ck_assert_int_eq(FAILED, s);
		msg = exchange_test_helper->sender->dequeue(exchange_test_helper->sender);
		ck_assert(!msg);
	}

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * The peers try to create a new CHILD_SA that looks exactly the same
 * as the existing one, so it won't get initiated.
 */
START_TEST(test_duplicate)
{
	child_cfg_t *child_cfg;
	child_cfg_create_t child = {
		.mode = MODE_TUNNEL,
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	assert_no_jobs_scheduled();
	assert_hook_not_called(child_updown);
	assert_hook_not_called(message);
	child_cfg = child_cfg_create("child", &child);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	child_cfg->add_traffic_selector(child_cfg, TRUE,
								traffic_selector_create_dynamic(0, 0, 65535));
	child_cfg->add_traffic_selector(child_cfg, FALSE,
								traffic_selector_create_dynamic(0, 0, 65535));
	child_cfg->get_ref(child_cfg);
	call_ikesa(a, initiate, child_cfg, NULL);
	assert_child_sa_count(a, 1);
	assert_sa_idle(a);

	call_ikesa(b, initiate, child_cfg, NULL);
	assert_child_sa_count(b, 1);
	assert_sa_idle(b);
	assert_hook();
	assert_hook();
	assert_scheduler();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * One of the peers tries to create a new CHILD_SA while the other concurrently
 * started to rekey the IKE_SA. TEMPORARY_FAILURE should be returned on both
 * sides and the peers should prepare to retry.
 */
START_TEST(test_collision_ike_rekey)
{
	child_cfg_t *child_cfg;
	child_cfg_create_t child = {
		.mode = MODE_TUNNEL,
		/* make sure this is not a duplicate of the initial CHILD_SA */
		.mark_out = { .value = 42, .mask = 0xffffffff },
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	assert_hook_not_called(child_updown);
	child_cfg = child_cfg_create("child", &child);
	child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
	child_cfg->add_traffic_selector(child_cfg, TRUE,
								traffic_selector_create_dynamic(0, 0, 65535));
	child_cfg->add_traffic_selector(child_cfg, FALSE,
								traffic_selector_create_dynamic(0, 0, 65535));
	call_ikesa(a, initiate, child_cfg, NULL);
	assert_child_sa_count(a, 1);
	assert_hook();

	call_ikesa(b, rekey);

	/* CREATE_CHILD_SA { SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_not_called(child_updown);
	assert_single_notify(OUT, TEMPORARY_FAILURE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 1);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Ni, KEi } */
	assert_single_notify(OUT, TEMPORARY_FAILURE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* <-- CREATE_CHILD_SA { N(TEMP_FAIL) } */
	assert_hook_not_called(child_updown);
	assert_jobs_scheduled(1);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 1);
	assert_scheduler();
	assert_hook();

	/* CREATE_CHILD_SA { N(TEMP_FAIL) } --> */
	assert_jobs_scheduled(1);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_ike_sa_state(b, IKE_ESTABLISHED);
	assert_scheduler();

	/* make sure no message was sent after handling the TEMPORARY_FAILURE and
	 * that the task to retry creating the CHILD_SA is queued and not active
	 * and it can't be initiated immediately */
	ck_assert(!exchange_test_helper->sender->dequeue(exchange_test_helper->sender));
	assert_num_tasks(a, 0, TASK_QUEUE_ACTIVE);
	assert_num_tasks(a, 1, TASK_QUEUE_QUEUED);
	call_ikesa(a, initiate, NULL, NULL);
	assert_num_tasks(a, 0, TASK_QUEUE_ACTIVE);

	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * One of the peers creates a new CHILD_SA using multiple key exchanges.
 */
START_TEST(test_multi_ke)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	child_cfg_create_t child = {
		.mode = MODE_TUNNEL,
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	assert_hook_not_called(child_updown);
	child_cfg = child_cfg_create("child", &child);
	child_cfg->add_proposal(child_cfg,
			proposal_create_from_string(PROTO_ESP,
										"aes256-sha256-modp3072-ke1_ecp256"));
	/* as configs are selected based on TS only, use a different protocol */
	child_cfg->add_traffic_selector(child_cfg, TRUE,
						traffic_selector_create_dynamic(6, 0, 65535));
	child_cfg->add_traffic_selector(child_cfg, FALSE,
						traffic_selector_create_dynamic(6, 0, 65535));
	call_ikesa(a, initiate, child_cfg, NULL);
	assert_child_sa_count(a, 1);
	peer_cfg = b->get_peer_cfg(b);
	peer_cfg->add_child_cfg(peer_cfg, child_cfg->get_ref(child_cfg));
	assert_hook();

	/* CREATE_CHILD_SA { SA, Ni, KEi, TSi, TSr } --> */
	assert_hook_not_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 1);

	/* <-- CREATE_CHILD_SA { SA, Nr, KEr, TSi, TSr, N(ADD_KE) } */
	assert_notify(IN, ADDITIONAL_KEY_EXCHANGE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 1);
	assert_hook();

	/* IKE_FOLLOWUP_KE { KEi N(ADD_KE) } --> */
	assert_hook_updown(child_updown, TRUE);
	assert_notify(IN, ADDITIONAL_KEY_EXCHANGE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 2);
	assert_hook();

	/* <-- IKE_FOLLOWUP_KE { KEr } */
	assert_hook_updown(child_updown, TRUE);
	assert_no_notify(IN, ADDITIONAL_KEY_EXCHANGE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 2);
	assert_hook();

	/* make sure no message was sent after creating the CHILD_SA */
	ck_assert(!exchange_test_helper->sender->dequeue(exchange_test_helper->sender));

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * A responder-side proposal mismatch is reported as received, while the
 * initiator's resulting NO_PROPOSAL_CHOSEN alert is reported as configured.
 */
START_TEST(test_proposal_mismatch_alert_provenance)
{
	child_cfg_create_t child = {
		.mode = MODE_TUNNEL,
	};
	proposal_mismatch_listener_t listener = {
		.listener = {
			.alert = proposal_mismatch_alert,
		},
		.expected = ALERT_PROPOSAL_MISMATCH_CHILD,
	};
	child_cfg_t *init_cfg, *resp_cfg;
	peer_cfg_t *peer_cfg;
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper, &a, &b, NULL);
	exchange_test_helper->add_listener(exchange_test_helper, &listener.listener);

	init_cfg = child_cfg_create("init", &child);
	init_cfg->add_proposal(init_cfg,
			proposal_create_from_string(PROTO_ESP, "aes128-sha256"));
	init_cfg->add_traffic_selector(init_cfg, TRUE,
			traffic_selector_create_dynamic(6, 0, 65535));
	init_cfg->add_traffic_selector(init_cfg, FALSE,
			traffic_selector_create_dynamic(6, 0, 65535));

	resp_cfg = child_cfg_create("resp", &child);
	resp_cfg->add_proposal(resp_cfg,
			proposal_create_from_string(PROTO_ESP, "aes256-sha384"));
	resp_cfg->add_traffic_selector(resp_cfg, TRUE,
			traffic_selector_create_dynamic(6, 0, 65535));
	resp_cfg->add_traffic_selector(resp_cfg, FALSE,
			traffic_selector_create_dynamic(6, 0, 65535));
	peer_cfg = b->get_peer_cfg(b);
	peer_cfg->add_child_cfg(peer_cfg, resp_cfg);

	call_ikesa(a, initiate, init_cfg, NULL);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	ck_assert_int_eq(listener.received, 1);
	ck_assert_int_eq(listener.received_proposals, 1);
	ck_assert_int_eq(listener.configured, 1);
	ck_assert_int_eq(listener.configured_proposals, 1);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * A responder-side IKE proposal mismatch is reported as received, while the
 * initiator's resulting NO_PROPOSAL_CHOSEN alert is reported as configured.
 */
START_TEST(test_ike_proposal_mismatch_alert_provenance)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.ike = "aes128-sha256-modp2048",
		},
		.responder = {
			.ike = "aes256-sha384-modp2048",
		},
	};
	proposal_mismatch_listener_t listener = {
		.listener = {
			.alert = proposal_mismatch_alert,
		},
		.expected = ALERT_PROPOSAL_MISMATCH_IKE,
	};
	child_cfg_t *child_cfg;
	ike_sa_id_t *id_a, *id_b;
	ike_sa_t *a, *b;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
													 &conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);
	exchange_test_helper->add_listener(exchange_test_helper, &listener.listener);

	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	ck_assert_int_eq(listener.received, 1);
	ck_assert_int_eq(listener.received_proposals, 1);
	ck_assert_int_eq(listener.configured, 1);
	ck_assert_int_eq(listener.configured_proposals, 1);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

Suite *child_create_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("child create");

	tc = tcase_create("pre-establish");
	tcase_add_loop_test(tc, test_pre_establish, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("initiate duplicate");
	tcase_add_test(tc, test_duplicate);
	suite_add_tcase(s, tc);

	tc = tcase_create("collisions ike rekey");
	tcase_add_test(tc, test_collision_ike_rekey);
	suite_add_tcase(s, tc);

	tc = tcase_create("multiple key exchanges");
	tcase_add_test(tc, test_multi_ke);
	suite_add_tcase(s, tc);

	tc = tcase_create("proposal mismatch alerts");
	tcase_add_test(tc, test_proposal_mismatch_alert_provenance);
	tcase_add_test(tc, test_ike_proposal_mismatch_alert_provenance);
	suite_add_tcase(s, tc);

	return s;
}
