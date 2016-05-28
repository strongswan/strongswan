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
 * Initiate rekeying the given IKE_SA.
 */
#define initiate_rekey(sa) ({ \
	assert_hook_not_called(ike_rekey); \
	call_ikesa(sa, rekey); \
	assert_ike_sa_state(a, IKE_REKEYING); \
	assert_hook(); \
})

/**
 * Regular IKE_SA rekeying either initiated by the original initiator or
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

	initiate_rekey(a);

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

/**
 * Both peers initiate the IKE_SA rekeying concurrently and should handle the
 * collision properly depending on the nonces.
 */
START_TEST(test_collision)
{
	ike_sa_t *a, *b, *sa;
	status_t status;

	exchange_test_helper->establish_sa(exchange_test_helper,
									   &a, &b, NULL);

	/* When rekeyings collide we get two IKE_SAs with a total of four nonces.
	 * The IKE_SA with the lowest nonce SHOULD be deleted by the peer that
	 * created that IKE_SA.  The replaced IKE_SA is deleted by the peer that
	 * initiated the surviving SA.
	 * Four nonces and SPIs are needed (SPI 1 and 2 are used for the initial
	 * IKE_SA):
	 *   N1/3 -----\    /----- N2/4
	 *              \--/-----> N3/5
	 *   N4/6 <-------/ /----- ...
	 *   ...  -----\
	 * We test this four times, each time a different nonce is the lowest.
	 */
	struct {
		/* Nonces used at each point */
		u_char nonces[4];
		/* SPIs of the deleted IKE_SAs (either redundant or replaced) */
		uint32_t del_a_i, del_a_r;
		uint32_t del_b_i, del_b_r;
		/* SPIs of the kept IKE_SA */
		uint32_t spi_i, spi_r;
	} data[] = {
		{ { 0x00, 0xFF, 0xFF, 0xFF }, 3, 5, 1, 2, 4, 6 },
		{ { 0xFF, 0x00, 0xFF, 0xFF }, 1, 2, 4, 6, 3, 5 },
		{ { 0xFF, 0xFF, 0x00, 0xFF }, 3, 5, 1, 2, 4, 6 },
		{ { 0xFF, 0xFF, 0xFF, 0x00 }, 1, 2, 4, 6, 3, 5 },
	};
	/* these should never get called as this results in a successful rekeying */
	assert_hook_not_called(ike_updown);
	assert_hook_not_called(child_updown);

	exchange_test_helper->nonce_first_byte = data[_i].nonces[0];
	initiate_rekey(a);
	exchange_test_helper->nonce_first_byte = data[_i].nonces[1];
	initiate_rekey(b);

	/* CREATE_CHILD_SA { SA, Ni, KEi } --> */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[2];
	assert_hook_not_called(ike_rekey);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_ike_sa_state(b, IKE_REKEYING);
	assert_child_sa_count(b, 1);
	assert_ike_sa_count(0);
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Ni, KEi } */
	exchange_test_helper->nonce_first_byte = data[_i].nonces[3];
	assert_hook_not_called(ike_rekey);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_ike_sa_state(a, IKE_REKEYING);
	assert_child_sa_count(a, 1);
	assert_ike_sa_count(0);
	assert_hook();

	/* simplify next steps by checking in original IKE_SAs */
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, a);
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, b);
	assert_ike_sa_count(2);

	/* <-- CREATE_CHILD_SA { SA, Nr, KEr } */
	assert_hook_rekey(ike_rekey, 1, data[_i].spi_i);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	/* as original initiator a is initiator of both SAs it could delete */
	sa = assert_ike_sa_checkout(data[_i].del_a_i, data[_i].del_a_r, TRUE);
	assert_ike_sa_state(sa, IKE_DELETING);
	assert_child_sa_count(sa, 0);
	/* if b won it will delete the original SA a initiated */
	sa = assert_ike_sa_checkout(data[_i].del_b_i, data[_i].del_b_r,
								data[_i].del_b_i == 1);
	assert_ike_sa_state(sa, IKE_REKEYED);
	assert_child_sa_count(sa, 0);
	sa = assert_ike_sa_checkout(data[_i].spi_i, data[_i].spi_r,
								data[_i].del_a_i == 1);
	assert_ike_sa_state(sa, IKE_ESTABLISHED);
	assert_child_sa_count(sa, 1);
	assert_ike_sa_count(4);
	assert_hook();

	/* CREATE_CHILD_SA { SA, Nr, KEr } --> */
	assert_hook_rekey(ike_rekey, 1, data[_i].spi_i);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* if b wins it deletes the SA originally initiated by a */
	sa = assert_ike_sa_checkout(data[_i].del_b_i, data[_i].del_b_r,
								data[_i].del_b_i != 1);
	assert_ike_sa_state(sa, IKE_DELETING);
	assert_child_sa_count(sa, 0);
	/* a only deletes SAs for which b is responder */
	sa = assert_ike_sa_checkout(data[_i].del_a_i, data[_i].del_a_r, FALSE);
	assert_ike_sa_state(sa, IKE_REKEYED);
	assert_child_sa_count(sa, 0);
	sa = assert_ike_sa_checkout(data[_i].spi_i, data[_i].spi_r,
								data[_i].del_b_i == 1);
	assert_ike_sa_state(sa, IKE_ESTABLISHED);
	assert_child_sa_count(sa, 1);
	assert_ike_sa_count(6);
	assert_hook();

	/* we don't expect this hook to get called anymore */
	assert_hook_not_called(ike_rekey);

	/* INFORMATIONAL { D } --> */
	assert_single_payload(IN, PLV2_DELETE);
	sa = assert_ike_sa_checkout(data[_i].del_a_i, data[_i].del_a_r, FALSE);
	status = exchange_test_helper->process_message(exchange_test_helper, sa,
												   NULL);
	ck_assert_int_eq(DESTROY_ME, status);
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, sa);
	assert_ike_sa_count(5);
	/* <-- INFORMATIONAL { D } */
	assert_single_payload(IN, PLV2_DELETE);
	sa = assert_ike_sa_checkout(data[_i].del_b_i, data[_i].del_b_r,
								data[_i].del_b_i == 1);
	status = exchange_test_helper->process_message(exchange_test_helper, sa,
												   NULL);
	ck_assert_int_eq(DESTROY_ME, status);
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, sa);
	assert_ike_sa_count(4);
	/* <-- INFORMATIONAL { } */
	assert_message_empty(IN);
	sa = assert_ike_sa_checkout(data[_i].del_a_i, data[_i].del_a_r, TRUE);
	status = exchange_test_helper->process_message(exchange_test_helper, sa,
												   NULL);
	ck_assert_int_eq(DESTROY_ME, status);
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, sa);
	assert_ike_sa_count(3);
	/* INFORMATIONAL { } --> */
	assert_message_empty(IN);
	sa = assert_ike_sa_checkout(data[_i].del_b_i, data[_i].del_b_r,
								data[_i].del_b_i != 1);
	status = exchange_test_helper->process_message(exchange_test_helper, sa,
												   NULL);
	ck_assert_int_eq(DESTROY_ME, status);
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, sa);
	assert_ike_sa_count(2);

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

	tc = tcase_create("collisions rekey");
	tcase_add_loop_test(tc, test_collision, 0, 4);
	suite_add_tcase(s, tc);

	return s;
}
