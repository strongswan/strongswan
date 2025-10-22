/*
 * Copyright (C) 2016-2025 Tobias Brunner
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

struct {
	char *init;
	char *resp;
	char *enabled;
	char *disabled;
} ike_auth_ke[] = {
	{ "aes128-sha256", "aes128-sha256", "aes128-sha256", "aes128-sha256" },
	{ "aes128-sha256-curve25519", "aes128-sha256-curve25519",
		"aes128-sha256-curve25519", "aes128-sha256" },
	{ "aes128-sha256-curve25519-none", "aes128-sha256",
		"aes128-sha256", "aes128-sha256" },
	{ "aes128-sha256", "aes128-sha256-curve25519-none", "aes128-sha256",
		"aes128-sha256" },
	{ "aes128-sha256-curve25519", "aes128-sha256", NULL, "aes128-sha256"  },
	{ "aes128-sha256", "aes128-sha256-curve25519", NULL, "aes128-sha256" },
};

/**
 * KE method negotiation during IKE_AUTH, which results in a selected KE method
 * or a mismatch.
 */
START_TEST(test_ike_auth_ke_enabled)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = ike_auth_ke[_i].init,
		},
		.responder = {
			.esp = ike_auth_ke[_i].resp,
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	proposal_t *selected;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	call_ikesa(a, initiate, child_cfg, NULL);

	/* IKE_SA_INIT --> */
	assert_notify(IN, CHILD_SA_PFS_INFO_SUPPORTED);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* <-- IKE_SA_INIT */
	assert_notify(IN, CHILD_SA_PFS_INFO_SUPPORTED);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	if (!ike_auth_ke[_i].enabled)
	{
		/* IKE_AUTH --> */
		assert_hook_not_called(child_updown);
		assert_no_payload(IN, PLV2_KEY_EXCHANGE);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);

		/* <-- IKE_AUTH */
		assert_notify(IN, NO_PROPOSAL_CHOSEN);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		assert_hook();
	}
	else
	{
		/* IKE_AUTH --> */
		assert_hook_called(child_updown);
		assert_no_payload(IN, PLV2_KEY_EXCHANGE);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		assert_child_sa_count(b, 1);
		assert_hook();

		/* <-- IKE_AUTH */
		assert_hook_called(child_updown);
		assert_no_payload(IN, PLV2_KEY_EXCHANGE);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		assert_child_sa_count(a, 1);
		assert_hook();

		child_sa = a->get_child_sa(a, PROTO_ESP, 1, TRUE);
		selected = proposal_create_from_string(PROTO_ESP, ike_auth_ke[_i].enabled);
		ck_assert(selected->equals(selected, child_sa->get_proposal(child_sa)));
		selected->destroy(selected);
	}

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * With KE method negotiation during IKE_AUTH disabled, we don't get any KE
 * methods or mismatches (until the SA is later rekeyed).
 */
START_TEST(test_ike_auth_ke_disabled)
{
	bool disable_init = _i > countof(ike_auth_ke);
	_i = _i % countof(ike_auth_ke);
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = ike_auth_ke[_i].init,
		},
		.responder = {
			.esp = ike_auth_ke[_i].resp,
		},
	};
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;
	child_sa_t *child_sa;
	proposal_t *selected;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	if (disable_init)
	{
		lib->settings->set_bool(lib->settings, "%s.child_sa_pfs_info",
								FALSE, lib->ns);
	}

	call_ikesa(a, initiate, child_cfg, NULL);

	/* IKE_SA_INIT --> */
	if (disable_init)
	{
		assert_no_notify(IN, CHILD_SA_PFS_INFO_SUPPORTED);
	}
	else
	{
		lib->settings->set_bool(lib->settings, "%s.child_sa_pfs_info",
								FALSE, lib->ns);
	}
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);

	/* <-- IKE_SA_INIT */
	assert_no_notify(IN, CHILD_SA_PFS_INFO_SUPPORTED);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	assert_no_payload(IN, PLV2_KEY_EXCHANGE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 1);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	assert_no_payload(IN, PLV2_KEY_EXCHANGE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 1);
	assert_hook();

	child_sa = a->get_child_sa(a, PROTO_ESP, 1, TRUE);
	selected = proposal_create_from_string(PROTO_ESP, ike_auth_ke[_i].disabled);
	ck_assert(selected->equals(selected, child_sa->get_proposal(child_sa)));
	selected->destroy(selected);

	assert_sa_idle(a);
	assert_sa_idle(b);

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

Suite *child_create_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("child create");

	tc = tcase_create("ike_auth ke");
	tcase_add_loop_test(tc, test_ike_auth_ke_enabled, 0, countof(ike_auth_ke));
	tcase_add_loop_test(tc, test_ike_auth_ke_disabled, 0, 2 * countof(ike_auth_ke));
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

	return s;
}
