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
#include <tests/utils/job_asserts.h>
#include <tests/utils/sa_asserts.h>

/**
 * Initiate rekeying the CHILD_SA with the given SPI on the given IKE_SA.
 */
#define initiate_rekey(sa, spi) ({ \
	assert_hook_not_called(child_updown); \
	assert_hook_not_called(child_rekey); \
	call_ikesa(sa, rekey_child_sa, PROTO_ESP, spi); \
	assert_child_sa_state(sa, spi, CHILD_REKEYING); \
	assert_hook(); \
	assert_hook(); \
})

/**
 * Regular CHILD_SA rekey either initiated by the original initiator or
 * responder of the IKE_SA.
 */
START_TEST(test_regular)
{
	ike_sa_t *a, *b;
	uint32_t spi_a = _i+1, spi_b = 2-_i;

	if (_i)
	{	/* responder rekeys the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, NULL);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, NULL);
	}
	initiate_rekey(a, spi_a);

	/* this should never get called as this results in a successful rekeying */
	assert_hook_not_called(child_updown);

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_called(child_rekey);
	assert_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, spi_b, CHILD_REKEYED);
	assert_child_sa_state(b, 4, CHILD_INSTALLED);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } */
	assert_hook_called(child_rekey);
	assert_no_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, spi_a, CHILD_DELETING);
	assert_child_sa_state(a, 3, CHILD_INSTALLED);
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_not_called(child_rekey);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 4, CHILD_INSTALLED);
	assert_child_sa_count(b, 1);
	assert_hook();
	/* <-- INFORMATIONAL { D } */
	assert_hook_not_called(child_rekey);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 3, CHILD_INSTALLED);
	assert_child_sa_count(a, 1);
	assert_hook();

	/* child_updown */
	assert_hook();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * CHILD_SA rekey where the responder does not agree with the DH group selected
 * by the initiator, either initiated by the original initiator or responder of
 * the IKE_SA.
 */
START_TEST(test_regular_ke_invalid)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp2048-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072-modp2048",
		},
	};
	ike_sa_t *a, *b;
	uint32_t spi_a = _i+1, spi_b = 2-_i;

	if (_i)
	{	/* responder rekeys the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, &conf);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, &conf);
	}
	initiate_rekey(a, spi_a);

	/* this should never get called as this results in a successful rekeying */
	assert_hook_not_called(child_updown);

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_not_called(child_rekey);
	assert_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, spi_b, CHILD_INSTALLED);
	assert_child_sa_count(b, 1);
	assert_hook();

	/* <-- CREATE_CHILD_SA { N(INVAL_KE) } */
	assert_hook_not_called(child_rekey);
	assert_single_notify(IN, INVALID_KE_PAYLOAD);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, spi_a, CHILD_REKEYING);
	assert_child_sa_count(a, 1);
	assert_hook();

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_called(child_rekey);
	assert_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, spi_b, CHILD_REKEYED);
	assert_child_sa_state(b, 6, CHILD_INSTALLED);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } */
	assert_hook_called(child_rekey);
	assert_no_notify(IN, REKEY_SA);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, spi_a, CHILD_DELETING);
	assert_child_sa_state(a, 5, CHILD_INSTALLED);
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_not_called(child_rekey);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 6, CHILD_INSTALLED);
	assert_child_sa_count(b, 1);
	assert_hook();
	/* <-- INFORMATIONAL { D } */
	assert_hook_not_called(child_rekey);
	assert_single_payload(IN, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 5, CHILD_INSTALLED);
	assert_child_sa_count(a, 1);
	assert_hook();

	/* child_updown */
	assert_hook();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Both peers initiate the CHILD_SA reekying concurrently and should handle
 * the collision properly depending on the nonces.
 */
START_TEST(test_collision)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	/* When rekeyings collide we get two CHILD_SAs with a total of four nonces.
	 * The CHILD_SA with the lowest nonce SHOULD be deleted by the peer that
	 * created that CHILD_SA.  The replaced CHILD_SA is deleted by the peer that
	 * initiated the surviving SA.
	 * Four nonces and SPIs are needed (SPI 1 and 2 are used for the initial
	 * CHILD_SA):
	 *   N1/3 -----\    /----- N2/4
	 *              \--/-----> N3/5
	 *   N4/6 <-------/ /----- ...
	 *   ...  -----\
	 * We test this four times, each time a different nonce is the lowest.
	 */
	struct {
		/* Nonces used at each point */
		u_char nonces[4];
		/* SPIs of the deleted CHILD_SA (either redundant or replaced) */
		uint32_t spi_del_a, spi_del_b;
		/* SPIs of the kept CHILD_SA */
		uint32_t spi_a, spi_b;
	} data[] = {
		{ { 0x00, 0xFF, 0xFF, 0xFF }, 3, 2, 6, 4 },
		{ { 0xFF, 0x00, 0xFF, 0xFF }, 1, 4, 3, 5 },
		{ { 0xFF, 0xFF, 0x00, 0xFF }, 3, 2, 6, 4 },
		{ { 0xFF, 0xFF, 0xFF, 0x00 }, 1, 4, 3, 5 },
	};

	exchange_test_helper->nonce_first_byte = data[_i].nonces[0];
	initiate_rekey(a, 1);
	exchange_test_helper->nonce_first_byte = data[_i].nonces[1];
	initiate_rekey(b, 2);

	/* this should never get called as this results in a successful rekeying */
	assert_hook_not_called(child_updown);

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[2];
	assert_hook_rekey(child_rekey, 2, 5);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 2, CHILD_REKEYED);
	assert_child_sa_state(b, 5, CHILD_INSTALLED);
	assert_hook();
	/* <-- CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[3];
	assert_hook_rekey(child_rekey, 1, 6);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 1, CHILD_REKEYED);
	assert_child_sa_state(a, 6, CHILD_INSTALLED);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } */
	if (data[_i].spi_del_a == 1)
	{	/* currently we call this again if we keep our own replacement as we
		 * already called it above */
		assert_hook_rekey(child_rekey, 1, data[_i].spi_a);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		assert_hook();
	}
	else
	{
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	}
	assert_child_sa_state(a, data[_i].spi_del_a, CHILD_DELETING);
	assert_child_sa_state(a, data[_i].spi_del_b, CHILD_REKEYED);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	/* CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } --> */
	if (data[_i].spi_del_b == 2)
	{
		assert_hook_rekey(child_rekey, 2, data[_i].spi_b);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		assert_hook();
	}
	else
	{
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	}
	assert_child_sa_state(b, data[_i].spi_del_b, CHILD_DELETING);
	assert_child_sa_state(b, data[_i].spi_del_a, CHILD_REKEYED);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);

	/* we don't expect this hook to get called anymore */
	assert_hook_not_called(child_rekey);
	/* INFORMATIONAL { D } --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, data[_i].spi_del_b, CHILD_DELETING);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);
	assert_child_sa_count(b, 2);
	/* <-- INFORMATIONAL { D } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, data[_i].spi_del_a, CHILD_DELETING);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	assert_child_sa_count(a, 2);
	/* <-- INFORMATIONAL { D } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	assert_child_sa_count(a, 1);
	/* INFORMATIONAL { D } --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);
	assert_child_sa_count(b, 1);

	/* child_rekey/child_updown */
	assert_hook();
	assert_hook();

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Both peers initiate the CHILD_SA reekying concurrently but the proposed DH
 * groups are not the same after handling the INVALID_KE_PAYLOAD they should
 * still handle the collision properly depending on the nonces.
 */
START_TEST(test_collision_ke_invalid)
{
	exchange_test_sa_conf_t conf = {
		.initiator = {
			.esp = "aes128-sha256-modp2048-modp3072",
		},
		.responder = {
			.esp = "aes128-sha256-modp3072-modp2048",
		},
	};
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, &conf);

	/* Eight nonces and SPIs are needed (SPI 1 and 2 are used for the initial
	 * CHILD_SA):
	 *     N1/3 -----\    /----- N2/4
	 *                \--/-----> N3/5
	 *     N4/6 <-------/  /---- INVAL_KE
	 * INVAL_KE -----\    /
	 *          <-----\--/
	 *     N5/7 -----\ \------->
	 *                \    /---- N6/8
	 *                 \--/----> N7/9
	 *    N8/10 <--------/ /---- ...
	 *      ... ------\
	 *
	 * We test this four times, each time a different nonce is the lowest.
	 */
	struct {
		/* Nonces used at each point */
		u_char nonces[4];
		/* SPIs of the deleted CHILD_SA (either redundant or replaced) */
		uint32_t spi_del_a, spi_del_b;
		/* SPIs of the kept CHILD_SA */
		uint32_t spi_a, spi_b;
	} data[] = {
		{ { 0x00, 0xFF, 0xFF, 0xFF }, 7, 2,10, 8 },
		{ { 0xFF, 0x00, 0xFF, 0xFF }, 1, 8, 7, 9 },
		{ { 0xFF, 0xFF, 0x00, 0xFF }, 7, 2,10, 8 },
		{ { 0xFF, 0xFF, 0xFF, 0x00 }, 1, 8, 7, 9 },
	};

	initiate_rekey(a, 1);
	initiate_rekey(b, 2);

	/* this should never get called as this results in a successful rekeying */
	assert_hook_not_called(child_updown);

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_not_called(child_rekey);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 2, CHILD_REKEYING);
	assert_child_sa_count(b, 1);
	assert_hook();
	/* <-- CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } */
	assert_hook_not_called(child_rekey);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 1, CHILD_REKEYING);
	assert_child_sa_count(a, 1);
	assert_hook();

	/* <-- CREATE_CHILD_SA { N(INVAL_KE) } */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[0];
	assert_hook_not_called(child_rekey);
	assert_single_notify(IN, INVALID_KE_PAYLOAD);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 1, CHILD_REKEYING);
	assert_child_sa_count(a, 1);
	assert_hook();
	/* CREATE_CHILD_SA { N(INVAL_KE) } --> */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[1];
	assert_hook_not_called(child_rekey);
	assert_single_notify(IN, INVALID_KE_PAYLOAD);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 2, CHILD_REKEYING);
	assert_child_sa_count(b, 1);
	assert_hook();

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[2];
	assert_hook_rekey(child_rekey, 2, 9);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, 2, CHILD_REKEYED);
	assert_child_sa_state(b, 9, CHILD_INSTALLED);
	assert_hook();
	/* <-- CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[3];
	assert_hook_rekey(child_rekey, 1, 10);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, 1, CHILD_REKEYED);
	assert_child_sa_state(a,10, CHILD_INSTALLED);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } */
	if (data[_i].spi_del_a == 1)
	{	/* currently we call this again if we keep our own replacement as we
		 * already called it above */
		assert_hook_rekey(child_rekey, 1, data[_i].spi_a);
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
		assert_hook();
	}
	else
	{
		exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	}
	assert_child_sa_state(a, data[_i].spi_del_a, CHILD_DELETING);
	assert_child_sa_state(a, data[_i].spi_del_b, CHILD_REKEYED);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	/* CREATE_CHILD_SA { SA, Nr, [KEr,] TSi, TSr } --> */
	if (data[_i].spi_del_b == 2)
	{
		assert_hook_rekey(child_rekey, 2, data[_i].spi_b);
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
		assert_hook();
	}
	else
	{
		exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	}
	assert_child_sa_state(b, data[_i].spi_del_b, CHILD_DELETING);
	assert_child_sa_state(b, data[_i].spi_del_a, CHILD_REKEYED);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);

	/* we don't expect this hook to get called anymore */
	assert_hook_not_called(child_rekey);
	/* INFORMATIONAL { D } --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, data[_i].spi_del_b, CHILD_DELETING);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);
	assert_child_sa_count(b, 2);
	/* <-- INFORMATIONAL { D } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, data[_i].spi_del_a, CHILD_DELETING);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	assert_child_sa_count(a, 2);
	/* <-- INFORMATIONAL { D } */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, data[_i].spi_a, CHILD_INSTALLED);
	assert_child_sa_count(a, 1);
	/* INFORMATIONAL { D } --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, data[_i].spi_b, CHILD_INSTALLED);
	assert_child_sa_count(b, 1);

	/* child_rekey/child_updown */
	assert_hook();
	assert_hook();

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * One of the hosts initiates a DELETE of the CHILD_SA the other peer is
 * concurrently trying to rekey.
 *
 *            rekey ----\       /---- delete
 *                       \-----/----> detect collision
 * detect collision <---------/ /---- TEMP_FAIL
 *           delete ----\      /
 *                       \----/----->
 *  aborts rekeying <--------/
 */
START_TEST(test_collision_delete)
{
	ike_sa_t *a, *b;
	uint32_t spi_a = _i+1, spi_b = 2-_i;

	if (_i)
	{	/* responder rekeys the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, NULL);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, NULL);
	}
	initiate_rekey(a, spi_a);
	call_ikesa(b, delete_child_sa, PROTO_ESP, spi_b, FALSE);
	assert_child_sa_state(b, spi_b, CHILD_DELETING);

	/* this should never get called as there is no successful rekeying on
	 * either side */
	assert_hook_not_called(child_rekey);

	/* RFC 7296, 2.25.1: If a peer receives a request to rekey a CHILD_SA that
	 * it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE.
	 */

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_not_called(child_updown);
	assert_notify(IN, REKEY_SA);
	assert_single_notify(OUT, TEMPORARY_FAILURE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, spi_b, CHILD_DELETING);
	assert_hook();

	/* RFC 7296, 2.25.1: If a peer receives a request to delete a CHILD_SA that
	 * it is currently trying to rekey, it SHOULD reply as usual, with a DELETE
	 * payload.
	 */

	/* <-- INFORMATIONAL { D } */
	assert_hook_updown(child_updown, FALSE);
	assert_single_payload(IN, PLV2_DELETE);
	assert_single_payload(OUT, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 0);
	assert_hook();

	/* <-- CREATE_CHILD_SA { N(TEMP_FAIL) } */
	assert_hook_not_called(child_updown);
	/* we don't expect a job to retry the rekeying */
	assert_no_jobs_scheduled();
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_scheduler();
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_updown(child_updown, FALSE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 0);
	assert_hook();

	/* child_rekey */
	assert_hook();

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * One of the hosts initiates a DELETE of the CHILD_SA the other peer is
 * concurrently trying to rekey.  However, the delete request is delayed or
 * dropped, so the peer doing the rekeying is unaware of the collision.
 *
 *            rekey ----\       /---- delete
 *                       \-----/----> detect collision
 *       reschedule <---------/------ TEMP_FAIL
 *                  <--------/
 *           delete ---------------->
 *
 * The job will not find the SA to retry rekeying.
 */
START_TEST(test_collision_delete_drop_delete)
{
	ike_sa_t *a, *b;
	message_t *msg;
	uint32_t spi_a = _i+1, spi_b = 2-_i;

	if (_i)
	{	/* responder rekeys the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, NULL);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, NULL);
	}
	initiate_rekey(a, spi_a);
	call_ikesa(b, delete_child_sa, PROTO_ESP, spi_b, FALSE);
	assert_child_sa_state(b, spi_b, CHILD_DELETING);

	/* this should never get called as there is no successful rekeying on
	 * either side */
	assert_hook_not_called(child_rekey);

	/* RFC 7296, 2.25.1: If a peer receives a request to rekey a CHILD_SA that
	 * it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE.
	 */

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> */
	assert_hook_not_called(child_updown);
	assert_notify(IN, REKEY_SA);
	assert_single_notify(OUT, TEMPORARY_FAILURE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_state(b, spi_b, CHILD_DELETING);
	assert_hook();

	/* delay the DELETE request */
	msg = exchange_test_helper->sender->dequeue(exchange_test_helper->sender);

	/* <-- CREATE_CHILD_SA { N(TEMP_FAIL) } */
	assert_hook_not_called(child_updown);
	/* we expect a job to retry the rekeying is scheduled */
	assert_jobs_scheduled(1);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_state(a, spi_a, CHILD_INSTALLED);
	assert_scheduler();
	assert_hook();

	/* <-- INFORMATIONAL { D } (delayed) */
	assert_hook_updown(child_updown, FALSE);
	assert_single_payload(IN, PLV2_DELETE);
	assert_single_payload(OUT, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, msg);
	assert_child_sa_count(a, 0);
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_updown(child_updown, FALSE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 0);
	assert_hook();

	/* child_rekey */
	assert_hook();

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * One of the hosts initiates a DELETE of the CHILD_SA the other peer is
 * concurrently trying to rekey.  However, the rekey request is delayed or
 * dropped, so the peer doing the deleting is unaware of the collision.
 *
 *            rekey ----\       /---- delete
 * detect collision <----\-----/
 *           delete ------\--------->
 *                         \-------->
 *                              /---- CHILD_SA_NOT_FOUND
 *  aborts rekeying <----------/
 */
 START_TEST(test_collision_delete_drop_rekey)
{
	ike_sa_t *a, *b;
	message_t *msg;
	uint32_t spi_a = _i+1, spi_b = 2-_i;

	if (_i)
	{	/* responder rekeys the CHILD_SA (SPI 2) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &b, &a, NULL);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b, NULL);
	}
	initiate_rekey(a, spi_a);
	call_ikesa(b, delete_child_sa, PROTO_ESP, spi_b, FALSE);
	assert_child_sa_state(b, spi_b, CHILD_DELETING);

	/* this should never get called as there is no successful rekeying on
	 * either side */
	assert_hook_not_called(child_rekey);

	/* delay the CREAE_CHILD_SA request */
	msg = exchange_test_helper->sender->dequeue(exchange_test_helper->sender);

	/* RFC 7296, 2.25.1: If a peer receives a request to delete a CHILD_SA that
	 * it is currently trying to rekey, it SHOULD reply as usual, with a DELETE
	 * payload.
	 */

	/* <-- INFORMATIONAL { D } */
	assert_hook_updown(child_updown, FALSE);
	assert_single_payload(IN, PLV2_DELETE);
	assert_single_payload(OUT, PLV2_DELETE);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_child_sa_count(a, 0);
	assert_hook();

	/* INFORMATIONAL { D } --> */
	assert_hook_updown(child_updown, FALSE);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_child_sa_count(b, 0);
	assert_hook();

	/* RFC 7296, 2.25.1: If a peer receives a to rekey a Child SA that does not
	 * exist, it SHOULD reply with CHILD_SA_NOT_FOUND.
	 */

	/* CREATE_CHILD_SA { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr } --> (delayed) */
	assert_hook_not_called(child_updown);
	assert_notify(IN, REKEY_SA);
	assert_single_notify(OUT, CHILD_SA_NOT_FOUND);
	exchange_test_helper->process_message(exchange_test_helper, b, msg);
	assert_hook();

	/* <-- CREATE_CHILD_SA { N(NO_CHILD_SA) } */
	assert_hook_not_called(child_updown);
	/* no jobs or tasks should get scheduled/queued */
	assert_no_jobs_scheduled();
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_scheduler();
	assert_hook();

	/* child_rekey */
	assert_hook();

	assert_sa_idle(a);
	assert_sa_idle(b);

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * FIXME: Not sure what we can do about the following:
 *
 * One of the hosts initiates a rekeying of a CHILD_SA and after responding to
 * it the other peer deletes the new SA.  However, the rekey response is
 * delayed or dropped, so the peer doing the rekeying receives a delete for an
 * unknown CHILD_SA and then has a rekeyed CHILD_SA that should not exist.
 *
 *            rekey ---------------->
 *                              /---- rekey
 *       unknown SA <----------/----- delete new SA
 *                  ----------/----->
 *                  <--------/
 *
 * The peers' states are now out of sync.
 *
 * Perhaps the rekey initiator could keep track of deletes for non-existing SAs
 * while rekeying and then check against the SPIs when handling the
 * CREATE_CHILD_SA response.
 */


Suite *child_rekey_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("child rekey");

	tc = tcase_create("regular");
	tcase_add_loop_test(tc, test_regular, 0, 2);
	tcase_add_loop_test(tc, test_regular_ke_invalid, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("collisions rekey");
	tcase_add_loop_test(tc, test_collision, 0, 4);
	tcase_add_loop_test(tc, test_collision_ke_invalid, 0, 4);
	suite_add_tcase(s, tc);

	tc = tcase_create("collisions delete");
	tcase_add_loop_test(tc, test_collision_delete, 0, 2);
	tcase_add_loop_test(tc, test_collision_delete_drop_delete, 0, 2);
	tcase_add_loop_test(tc, test_collision_delete_drop_rekey, 0, 2);
	suite_add_tcase(s, tc);

	return s;
}
