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

#include <config/proposal.h>

static struct {
	protocol_id_t proto;
	char *self;
	char *other;
	char *expected;
} select_data[] = {
	{ PROTO_ESP, "aes128", "aes128", "aes128" },
	{ PROTO_ESP, "aes128", "aes256", NULL },
	{ PROTO_ESP, "aes128-aes256", "aes256-aes128", "aes128" },
	{ PROTO_ESP, "aes256-aes128", "aes128-aes256", "aes256" },
	{ PROTO_ESP, "aes128-aes256-sha1-sha256", "aes256-aes128-sha256-sha1", "aes128-sha1" },
	{ PROTO_ESP, "aes256-aes128-sha256-sha1", "aes128-aes256-sha1-sha256", "aes256-sha256" },
	{ PROTO_ESP, "aes128-sha256-modp3072", "aes128-sha256", NULL },
	{ PROTO_ESP, "aes128-sha256", "aes128-sha256-modp3072", NULL },
	{ PROTO_ESP, "aes128-sha256-modp3072", "aes128-sha256-modpnone", NULL },
	{ PROTO_ESP, "aes128-sha256-modpnone", "aes128-sha256-modp3072", NULL },
	{ PROTO_ESP, "aes128-sha256-modp3072-modpnone", "aes128-sha256", "aes128-sha256" },
	{ PROTO_ESP, "aes128-sha256", "aes128-sha256-modp3072-modpnone", "aes128-sha256" },
	{ PROTO_ESP, "aes128-sha256-modp3072-modpnone", "aes128-sha256-modpnone-modp3072", "aes128-sha256-modp3072" },
	{ PROTO_ESP, "aes128-sha256-modpnone-modp3072", "aes128-sha256-modp3072-modpnone", "aes128-sha256-modpnone" },
	{ PROTO_IKE, "aes128", NULL, NULL },
	{ PROTO_IKE, "aes128-sha256", NULL, NULL },
	{ PROTO_IKE, "aes128-sha256-modpnone", NULL, NULL },
	{ PROTO_IKE, "aes128-sha256-modp3072", "aes128-sha256-modp3072", "aes128-sha256-modp3072" },
	{ PROTO_IKE, "aes128-sha256-modp3072", "aes128-sha256-modp3072-modpnone", "aes128-sha256-modp3072" },
	{ PROTO_IKE, "aes128-sha256-modp3072-modpnone", "aes128-sha256-modp3072", "aes128-sha256-modp3072" },
};

START_TEST(test_select)
{
	proposal_t *self, *other, *selected, *expected;

	self = proposal_create_from_string(select_data[_i].proto,
									   select_data[_i].self);
	if (!select_data[_i].other)
	{
		ck_assert(!self);
		return;
	}
	other = proposal_create_from_string(select_data[_i].proto,
										select_data[_i].other);
	selected = self->select(self, other, FALSE);
	if (select_data[_i].expected)
	{
		expected = proposal_create_from_string(select_data[_i].proto,
											   select_data[_i].expected);
		ck_assert(selected);
		ck_assert_msg(expected->equals(expected, selected), "proposal %P does "
					  "not match expected %P", selected, expected);
		expected->destroy(expected);
	}
	else
	{
		ck_assert(!selected);
	}
	DESTROY_IF(selected);
	other->destroy(other);
	self->destroy(self);
}
END_TEST

Suite *proposal_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("proposal");

	tc = tcase_create("select");
	tcase_add_loop_test(tc, test_select, 0, countof(select_data));
	suite_add_tcase(s, tc);

	return s;
}
