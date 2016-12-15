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
	char *proposal;
	char *expected;
} create_data[] = {
	{ PROTO_IKE, "", NULL },
	{ PROTO_IKE, "sha256", NULL },
	{ PROTO_IKE, "sha256-modp3072", NULL },
	{ PROTO_IKE, "null-sha256-modp3072", "IKE:NULL/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072" },
	{ PROTO_IKE, "aes128", NULL },
	{ PROTO_IKE, "aes128-sha256", NULL },
	{ PROTO_IKE, "aes128-sha256-modpnone", NULL },
	{ PROTO_IKE, "aes128-sha256-modp3072", "IKE:AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072" },
	{ PROTO_IKE, "aes128-sha256-prfsha384-modp3072", "IKE:AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_384/MODP_3072" },
	{ PROTO_IKE, "aes128gcm16-modp3072", NULL },
	{ PROTO_IKE, "aes128gcm16-prfsha256-modp3072", "IKE:AES_GCM_16_128/PRF_HMAC_SHA2_256/MODP_3072" },
	{ PROTO_IKE, "aes128gcm16-sha256-modp3072", "IKE:AES_GCM_16_128/PRF_HMAC_SHA2_256/MODP_3072" },
	{ PROTO_IKE, "aes128gcm16-aes128-modp3072", NULL },
	{ PROTO_IKE, "aes128gcm16-aes128-sha256-modp3072", NULL },
	{ PROTO_ESP, "", NULL },
	{ PROTO_ESP, "sha256", NULL },
	{ PROTO_ESP, "aes128-sha256", "ESP:AES_CBC_128/HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_ESP, "aes128-sha256-esn", "ESP:AES_CBC_128/HMAC_SHA2_256_128/EXT_SEQ" },
	{ PROTO_ESP, "aes128-sha256-noesn", "ESP:AES_CBC_128/HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_ESP, "aes128-sha256-esn-noesn", "ESP:AES_CBC_128/HMAC_SHA2_256_128/EXT_SEQ/NO_EXT_SEQ" },
	{ PROTO_ESP, "aes128-sha256-prfsha256-modp3072", "ESP:AES_CBC_128/HMAC_SHA2_256_128/MODP_3072/NO_EXT_SEQ" },
	{ PROTO_ESP, "aes128gcm16-aes128-sha256-modp3072", NULL },
	{ PROTO_ESP, "aes128gmac", "ESP:NULL_AES_GMAC_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "", NULL },
	{ PROTO_AH,  "aes128", NULL },
	{ PROTO_AH,  "aes128-sha256", "AH:HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "sha256-sha1", "AH:HMAC_SHA2_256_128/HMAC_SHA1_96/NO_EXT_SEQ" },
	{ PROTO_AH,  "aes128gmac-sha256", "AH:AES_128_GMAC/HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "aes128gmac-sha256-prfsha256", "AH:AES_128_GMAC/HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "aes128gmac-aes256gmac-aes128-sha256", "AH:AES_128_GMAC/AES_256_GMAC/HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "sha256-esn", "AH:HMAC_SHA2_256_128/EXT_SEQ" },
	{ PROTO_AH,  "sha256-noesn", "AH:HMAC_SHA2_256_128/NO_EXT_SEQ" },
	{ PROTO_AH,  "sha256-esn-noesn", "AH:HMAC_SHA2_256_128/EXT_SEQ/NO_EXT_SEQ" },
};

START_TEST(test_create_from_string)
{
	proposal_t *proposal;
	char str[BUF_LEN];

	proposal = proposal_create_from_string(create_data[_i].proto,
										   create_data[_i].proposal);
	if (!create_data[_i].expected)
	{
		ck_assert(!proposal);
		return;
	}
	snprintf(str, sizeof(str), "%P", proposal);
	ck_assert_str_eq(create_data[_i].expected, str);
	proposal->destroy(proposal);
}
END_TEST

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
	{ PROTO_IKE, "aes128-sha256-modp3072", "aes128-sha256-modp3072", "aes128-sha256-modp3072" },
	{ PROTO_IKE, "aes128-sha256-modp3072", "aes128-sha256-modp3072-modpnone", "aes128-sha256-modp3072" },
	{ PROTO_IKE, "aes128-sha256-modp3072-modpnone", "aes128-sha256-modp3072", "aes128-sha256-modp3072" },
};

START_TEST(test_select)
{
	proposal_t *self, *other, *selected, *expected;

	self = proposal_create_from_string(select_data[_i].proto,
									   select_data[_i].self);
	other = proposal_create_from_string(select_data[_i].proto,
										select_data[_i].other);
	selected = self->select(self, other, TRUE, FALSE);
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

START_TEST(test_select_spi)
{
	proposal_t *self, *other, *selected;

	self = proposal_create_from_string(PROTO_ESP, "aes128-sha256-modp3072");
	other = proposal_create_from_string(PROTO_ESP, "aes128-sha256-modp3072");
	other->set_spi(other, 0x12345678);

	selected = self->select(self, other, TRUE, FALSE);
	ck_assert(selected);
	ck_assert_int_eq(selected->get_spi(selected), other->get_spi(other));
	selected->destroy(selected);

	selected = self->select(self, other, FALSE, FALSE);
	ck_assert(selected);
	ck_assert_int_eq(selected->get_spi(selected), self->get_spi(self));
	selected->destroy(selected);

	other->destroy(other);
	self->destroy(self);
}
END_TEST

Suite *proposal_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("proposal");

	tc = tcase_create("create_from_string");
	tcase_add_loop_test(tc, test_create_from_string, 0, countof(create_data));
	suite_add_tcase(s, tc);

	tc = tcase_create("select");
	tcase_add_loop_test(tc, test_select, 0, countof(select_data));
	tcase_add_test(tc, test_select_spi);
	suite_add_tcase(s, tc);

	return s;
}
