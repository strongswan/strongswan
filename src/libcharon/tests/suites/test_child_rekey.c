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
										   &b, &a);
	}
	else
	{	/* initiator rekeys the CHILD_SA (SPI 1) */
		exchange_test_helper->establish_sa(exchange_test_helper,
										   &a, &b);
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
 * Both peers initiate the CHILD_SA reekying concurrently and should handle
 * the collision properly depending on the nonces.
 */
START_TEST(test_collision)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b);

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

Suite *child_rekey_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("child rekey");

	tc = tcase_create("regular");
	tcase_add_loop_test(tc, test_regular, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("collisions");
	tcase_add_loop_test(tc, test_collision, 0, 4);
	suite_add_tcase(s, tc);

	return s;
}
