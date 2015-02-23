/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include <selectors/traffic_selector.h>


static void verify(const char *str, const char *alt, traffic_selector_t *ts)
{
	char buf[512];

	ck_assert(ts != NULL);
	snprintf(buf, sizeof(buf), "%R", ts);
	ts->destroy(ts);
	if (!streq(buf, str) && !streq(buf, alt))
	{
		fail("%s != %s or %s", buf, str, alt);
	}
}

START_TEST(test_create_from_string)
{
	verify("10.1.0.0/16[tcp/http]", "10.1.0.0/16[6/80]",
		traffic_selector_create_from_string(IPPROTO_TCP, TS_IPV4_ADDR_RANGE,
							"10.1.0.0", 80, "10.1.255.255", 80));
	verify("10.1.0.1..10.1.0.99[udp/1234-1235]",
		   "10.1.0.1..10.1.0.99[17/1234-1235]",
		traffic_selector_create_from_string(IPPROTO_UDP, TS_IPV4_ADDR_RANGE,
							"10.1.0.1", 1234, "10.1.0.99", 1235));
	verify("fec1::/64", NULL,
		traffic_selector_create_from_string(0, TS_IPV6_ADDR_RANGE,
							"fec1::", 0, "fec1::ffff:ffff:ffff:ffff", 65535));
}
END_TEST

START_TEST(test_create_from_cidr)
{
	verify("10.1.0.0/16", NULL,
		traffic_selector_create_from_cidr("10.1.0.0/16", 0, 0, 65535));
	verify("10.1.0.1/32[udp/1234-1235]", "10.1.0.1/32[17/1234-1235]",
		traffic_selector_create_from_cidr("10.1.0.1/32", IPPROTO_UDP,
										  1234, 1235));
}
END_TEST

START_TEST(test_create_from_bytes)
{
	verify("10.1.0.0/16", NULL,
		traffic_selector_create_from_bytes(0, TS_IPV4_ADDR_RANGE,
			chunk_from_chars(0x0a,0x01,0x00,0x00), 0,
			chunk_from_chars(0x0a,0x01,0xff,0xff), 65535));
}
END_TEST

START_TEST(test_create_from_subnet)
{
	verify("10.1.0.0/16", NULL,
		traffic_selector_create_from_subnet(
					host_create_from_string("10.1.0.0", 0), 16, 0, 0, 65535));
}
END_TEST


START_TEST(test_subset)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.1.0.0/16", 0, 0, 65535);
	b = traffic_selector_create_from_cidr("10.1.5.0/24", 0, 0, 65535);
	verify("10.1.5.0/24", NULL, a->get_subset(a, b));
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_port)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.0.0.0/8", IPPROTO_TCP, 55, 60);
	b = traffic_selector_create_from_cidr("10.2.7.16/30", 0, 0, 65535);
	verify("10.2.7.16/30[tcp/55-60]", "10.2.7.16/30[6/55-60]",
		a->get_subset(a, b));
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_equal)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.1.0.0/16", IPPROTO_TCP, 80, 80);
	b = traffic_selector_create_from_cidr("10.1.0.0/16", IPPROTO_TCP, 80, 80);
	verify("10.1.0.0/16[tcp/http]", "10.1.0.0/16[6/80]", a->get_subset(a, b));
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_nonet)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.1.0.0/16", 0, 0, 65535);
	b = traffic_selector_create_from_cidr("10.2.0.0/16", 0, 0, 65535);
	ck_assert(a->get_subset(a, b) == NULL);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_noport)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.1.0.0/16", 0, 0, 9999);
	b = traffic_selector_create_from_cidr("10.1.0.0/16", 0, 10000, 65535);
	ck_assert(a->get_subset(a, b) == NULL);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_noproto)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("10.1.0.0/16", IPPROTO_TCP, 0, 65535);
	b = traffic_selector_create_from_cidr("10.1.0.0/16", IPPROTO_UDP, 0, 65535);
	ck_assert(a->get_subset(a, b) == NULL);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

START_TEST(test_subset_nofamily)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr("0.0.0.0/0", 0, 0, 65535);
	b = traffic_selector_create_from_cidr("::/0", 0, 0, 65535);
	ck_assert(a->get_subset(a, b) == NULL);
	a->destroy(a);
	b->destroy(b);
}
END_TEST

struct {
	char *net;
	char *host;
	bool inc;
} include_tests[] = {
	{ "0.0.0.0/0",		"192.168.1.2",			TRUE },
	{ "::/0",			"fec2::1",				TRUE },
	{ "fec2::/64",		"fec2::afaf",			TRUE },
	{ "10.1.0.0/16",	"10.1.0.1",				TRUE },
	{ "10.5.6.7/32",	"10.5.6.7",				TRUE },
	{ "0.0.0.0/0",		"fec2::1",				FALSE },
	{ "::/0",			"1.2.3.4",				FALSE },
	{ "10.0.0.0/16",	"10.1.0.0",				FALSE },
	{ "fec2::/64",		"fec2:0:0:1::afaf",		FALSE },
};

START_TEST(test_includes)
{
	traffic_selector_t *ts;
	host_t *h;

	ts = traffic_selector_create_from_cidr(include_tests[_i].net, 0, 0, 65535);
	h = host_create_from_string(include_tests[_i].host, 0);
	ck_assert(ts->includes(ts, h) == include_tests[_i].inc);
	ts->destroy(ts);
	h->destroy(h);
}
END_TEST

struct {
	int res;
	struct {
		char *net;
		u_int8_t proto;
		u_int16_t from_port;
		u_int16_t to_port;
	} a, b;
} cmp_tests[] = {
	{  0, { "10.0.0.0/8", 0, 0, 65535 },	{ "10.0.0.0/8", 0, 0, 65535 },	},
	{  0, { "10.0.0.0/8", 17, 123, 456 },	{ "10.0.0.0/8", 17, 123, 456 },	},
	{  0, { "fec2::/64", 0, 0, 65535 },		{ "fec2::/64", 0, 0, 65535 },	},
	{  0, { "fec2::/64", 4, 0, 65535 },		{ "fec2::/64", 4, 0, 65535 },	},

	{ -1, { "1.0.0.0/8", 0, 0, 65535 },		{ "2.0.0.0/8", 0, 0, 65535 },	},
	{  1, { "2.0.0.0/8", 0, 0, 65535 },		{ "1.0.0.0/8", 0, 0, 65535 },	},
	{ -1, { "1.0.0.0/8", 0, 0, 65535 },		{ "1.0.0.0/16", 0, 0, 65535 },	},
	{  1, { "1.0.0.0/16", 0, 0, 65535 },	{ "1.0.0.0/8", 0, 0, 65535 },	},

	{ -1, { "10.0.0.0/8", 0, 0, 65535 },	{ "fec2::/64", 0, 0, 65535 },	},
	{  1, { "fec2::/64", 0, 0, 65535 },		{ "10.0.0.0/8", 0, 0, 65535 },	},

	{ -1, { "10.0.0.0/8", 16, 123, 456 },	{ "10.0.0.0/8", 17, 123, 456 },	},
	{  1, { "fec2::/64", 5, 0, 65535 },		{ "fec2::/64", 4, 0, 65535 },	},

	{ -1, { "10.0.0.0/8", 17, 111, 456 },	{ "10.0.0.0/8", 17, 222, 456 },	},
	{  1, { "fec2::/64", 17, 555, 65535 },	{ "fec2::/64", 17, 444, 65535 },},

	{ -1, { "10.0.0.0/8", 17, 55, 65535 },	{ "10.0.0.0/8", 17, 55, 666 },	},
	{  1, { "fec2::/64", 17, 55, 111 },		{ "fec2::/64", 17, 55, 4567 },	},

};

START_TEST(test_cmp)
{
	traffic_selector_t *a, *b;

	a = traffic_selector_create_from_cidr(
						cmp_tests[_i].a.net, cmp_tests[_i].a.proto,
						cmp_tests[_i].a.from_port, cmp_tests[_i].a.to_port);
	b = traffic_selector_create_from_cidr(
						cmp_tests[_i].b.net, cmp_tests[_i].b.proto,
						cmp_tests[_i].b.from_port, cmp_tests[_i].b.to_port);
	switch (cmp_tests[_i].res)
	{
		case 0:
			ck_assert(traffic_selector_cmp(a, b, NULL) == 0);
			break;
		case 1:
			ck_assert(traffic_selector_cmp(a, b, NULL) > 0);
			break;
		case -1:
			ck_assert(traffic_selector_cmp(a, b, NULL) < 0);
			break;
	}
	a->destroy(a);
	b->destroy(b);
}
END_TEST

Suite *traffic_selector_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("traffic selector");

	tc = tcase_create("create");
	tcase_add_test(tc, test_create_from_string);
	tcase_add_test(tc, test_create_from_cidr);
	tcase_add_test(tc, test_create_from_bytes);
	tcase_add_test(tc, test_create_from_subnet);
	suite_add_tcase(s, tc);

	tc = tcase_create("subset");
	tcase_add_test(tc, test_subset);
	tcase_add_test(tc, test_subset_port);
	tcase_add_test(tc, test_subset_equal);
	tcase_add_test(tc, test_subset_nonet);
	tcase_add_test(tc, test_subset_noport);
	tcase_add_test(tc, test_subset_noproto);
	tcase_add_test(tc, test_subset_nofamily);
	suite_add_tcase(s, tc);

	tc = tcase_create("includes");
	tcase_add_loop_test(tc, test_includes, 0, countof(include_tests));
	suite_add_tcase(s, tc);

	tc = tcase_create("cmp");
	tcase_add_loop_test(tc, test_cmp, 0, countof(cmp_tests));
	suite_add_tcase(s, tc);

	return s;
}
