/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include <networking/host.h>

/*******************************************************************************
 * host_create_netmask
 */

static void verify_netmask(chunk_t addr, int mask)
{
	int byte, bit;

	for (byte = 0; byte < addr.len; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			int val = (addr.ptr[byte] >> bit) & 0x01;
			if (mask-- > 0)
			{
				ck_assert_int_eq(val, 1);
			}
			else
			{
				ck_assert_int_eq(val, 0);
			}
		}
	}
}

static void test_create_netmask(int family)
{
	host_t *netmask;
	int i, len = (family == AF_INET) ? 32 : 128;

	netmask = host_create_netmask(family, -1);
	ck_assert(netmask == NULL);
	for (i = 0; i <= len; i++)
	{
		netmask = host_create_netmask(family, i);
		verify_netmask(netmask->get_address(netmask), i);
		netmask->destroy(netmask);
	}
	netmask = host_create_netmask(family, len + 1);
	ck_assert(netmask == NULL);
}

START_TEST(test_create_netmask_v4)
{
	test_create_netmask(AF_INET);
}
END_TEST

START_TEST(test_create_netmask_v6)
{
	test_create_netmask(AF_INET6);
}
END_TEST

START_TEST(test_create_netmask_other)
{
	host_t *netmask;

	netmask = host_create_netmask(AF_UNSPEC, 0);
	ck_assert(netmask == NULL);
}
END_TEST

Suite *host_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("host");

	tc = tcase_create("host_create_netmask");
	tcase_add_test(tc, test_create_netmask_v4);
	tcase_add_test(tc, test_create_netmask_v6);
	tcase_add_test(tc, test_create_netmask_other);
	suite_add_tcase(s, tc);

	return s;
}
