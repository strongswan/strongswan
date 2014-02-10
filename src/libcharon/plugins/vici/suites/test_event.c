/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include <test_suite.h>

#include "../vici_dispatcher.h"
#include "../libvici.h"

#include <unistd.h>

#define URI "unix:///tmp/strongswan-vici-event-test"

static void event_cb(void *user, char *name, vici_res_t *ev)
{
	int *count = (int*)user;

	ck_assert_str_eq(name, "test");
	ck_assert(vici_parse(ev) == VICI_PARSE_KEY_VALUE);
	ck_assert_str_eq(vici_parse_name(ev), "key1");
	ck_assert_str_eq(vici_parse_value_str(ev), "value1");
	ck_assert(vici_parse(ev) == VICI_PARSE_END);

	(*count)++;
}

START_TEST(test_event)
{
	vici_dispatcher_t *dispatcher;
	vici_conn_t *conn;
	int count = 0;

	lib->processor->set_threads(lib->processor, 8);

	dispatcher = vici_dispatcher_create(URI);
	ck_assert(dispatcher);

	dispatcher->manage_event(dispatcher, "test", TRUE);

	vici_init();
	conn = vici_connect(URI);
	ck_assert(conn);

	ck_assert(vici_register(conn, "test", event_cb, &count) == 0);
	ck_assert(vici_register(conn, "nonexistent", event_cb, &count) != 0);

	dispatcher->raise_event(dispatcher, "test", 0, vici_message_create_from_args(
		 VICI_KEY_VALUE, "key1", chunk_from_str("value1"),
		VICI_END));

	while (count == 0)
	{
		usleep(1000);
	}

	vici_disconnect(conn);

	dispatcher->manage_event(dispatcher, "test", FALSE);

	lib->processor->cancel(lib->processor);
	dispatcher->destroy(dispatcher);

	vici_deinit();
}
END_TEST

START_TEST(test_stress)
{
	vici_dispatcher_t *dispatcher;
	vici_conn_t *conn;
	int count = 0, i, total = 50;

	lib->processor->set_threads(lib->processor, 8);

	dispatcher = vici_dispatcher_create(URI);
	ck_assert(dispatcher);

	dispatcher->manage_event(dispatcher, "test", TRUE);
	dispatcher->manage_event(dispatcher, "dummy", TRUE);

	vici_init();
	conn = vici_connect(URI);
	ck_assert(conn);

	vici_register(conn, "test", event_cb, &count);

	for (i = 0; i < total; i++)
	{
		/* do some event re/deregistration in between */
		ck_assert(vici_register(conn, "dummy", event_cb, NULL) == 0);

		dispatcher->raise_event(dispatcher, "test", 0,
			vici_message_create_from_args(
				 VICI_KEY_VALUE, "key1", chunk_from_str("value1"),
				VICI_END));

		ck_assert(vici_register(conn, "dummy", NULL, NULL) == 0);
	}

	while (count < total)
	{
		usleep(1000);
	}

	vici_disconnect(conn);

	dispatcher->manage_event(dispatcher, "test", FALSE);
	dispatcher->manage_event(dispatcher, "dummy", FALSE);

	lib->processor->cancel(lib->processor);
	dispatcher->destroy(dispatcher);

	vici_deinit();
}
END_TEST

Suite *event_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("vici events");

	tc = tcase_create("single");
	tcase_add_test(tc, test_event);
	suite_add_tcase(s, tc);

	tc = tcase_create("stress");
	tcase_add_test(tc, test_stress);
	suite_add_tcase(s, tc);

	return s;
}
