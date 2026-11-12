/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Regression tests for concurrent IKEv2 requests and responses.
 */

#include "test_suite.h"

#include <daemon.h>
#include <encoding/message.h>
#include <threading/semaphore.h>
#include <threading/thread.h>

static semaphore_t *message_id_read;

/*
 * checkout_by_message() reads the ID while holding the entry's segment lock.
 * Once this signals, checkin() must wait until the duplicate check has either
 * rejected the message or started waiting for the checked-out SA.
 */
static uint32_t signal_message_id(message_t *message)
{
	message_id_read->post(message_id_read);
	return 170;
}

static message_t *create_message(ike_sa_t *sa, bool request)
{
	message_t *message;
	ike_sa_id_t *id;

	message = message_create(IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION);
	id = sa->get_id(sa)->clone(sa->get_id(sa));
	id->switch_initiator(id);
	message->set_ike_sa_id(message, id);
	id->destroy(id);
	message->set_exchange_type(message, CREATE_CHILD_SA);
	message->set_message_id(message, 170);
	message->set_request(message, request);
	return message;
}

static void *checkout_message(void *arg)
{
	ike_sa_manager_t *manager = charon->ike_sa_manager;
	ike_sa_t *sa;

	sa = manager->checkout_by_message(manager, arg);
	if (sa)
	{
		manager->checkin(manager, sa);
	}
	return sa;
}

START_TEST(test_same_mid_request_response)
{
	ike_sa_manager_t *manager = charon->ike_sa_manager;
	ike_sa_t *sa, *first, *second, *duplicate;
	ike_sa_id_t *id;
	message_t *first_message, *second_message;
	thread_t *thread;
	bool accepted;

	sa = manager->create_new(manager, IKEV2, TRUE);
	ck_assert(sa);
	id = sa->get_id(sa);
	id->set_responder_spi(id, 2);
	manager->checkout_new(manager, sa);
	manager->checkin(manager, sa);

	first_message = create_message(sa, _i);
	second_message = create_message(sa, !_i);
	first = manager->checkout_by_message(manager, first_message);
	ck_assert(first == sa);

	/* A duplicate of the same request/response must still be rejected. */
	duplicate = manager->checkout_by_message(manager, first_message);
	ck_assert(!duplicate);

	message_id_read = semaphore_create(0);
	second_message->get_message_id = signal_message_id;
	thread = thread_create(checkout_message, second_message);
	message_id_read->wait(message_id_read);
	manager->checkin(manager, first);
	second = thread->join(thread);
	accepted = second == first;

	/* Clean up before asserting so failures don't leave an SA checked out. */
	sa = manager->checkout(manager, id);
	manager->checkin_and_destroy(manager, sa);
	first_message->destroy(first_message);
	second_message->destroy(second_message);
	message_id_read->destroy(message_id_read);
	ck_assert(accepted);
}
END_TEST

Suite *ike_sa_manager_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("ike_sa_manager");
	tc = tcase_create("concurrent messages");
	tcase_add_loop_test(tc, test_same_mid_request_response, 0, 2);
	suite_add_tcase(s, tc);
	return s;
}
