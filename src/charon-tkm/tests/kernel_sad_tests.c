/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <check.h>

#include "tkm_kernel_sad.h"

START_TEST(test_sad_creation)
{
	tkm_kernel_sad_t *sad = NULL;

	sad = tkm_kernel_sad_create();
	fail_if(!sad, "Error creating tkm kernel SAD");

	sad->destroy(sad);
}
END_TEST

START_TEST(test_insert)
{
	host_t *addr = host_create_from_string("127.0.0.1", 1024);
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();

	fail_unless(sad->insert(sad, 1, addr, addr, 42, 50),
				"Error inserting SAD entry");

	sad->destroy(sad);
	addr->destroy(addr);
}
END_TEST

START_TEST(test_insert_duplicate)
{
	host_t *addr = host_create_from_string("127.0.0.1", 1024);
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();

	fail_unless(sad->insert(sad, 1, addr, addr, 42, 50),
				"Error inserting SAD entry");
	fail_if(sad->insert(sad, 1, addr, addr, 42, 50),
			"Expected error inserting duplicate entry");

	sad->destroy(sad);
	addr->destroy(addr);
}
END_TEST

START_TEST(test_get_esa_id)
{
	host_t *addr = host_create_from_string("127.0.0.1", 1024);
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();
	fail_unless(sad->insert(sad, 23, addr, addr, 42, 50),
				"Error inserting SAD entry");
	fail_unless(sad->get_esa_id(sad, addr, addr, 42, 50) == 23,
				"Error getting esa id");
	sad->destroy(sad);
	addr->destroy(addr);
}
END_TEST

START_TEST(test_get_esa_id_nonexistent)
{
	host_t *addr = host_create_from_string("127.0.0.1", 1024);
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();
	fail_unless(sad->get_esa_id(sad, addr, addr, 42, 50) == 0,
				"Got esa id for nonexistent SAD entry");
	sad->destroy(sad);
	addr->destroy(addr);
}
END_TEST

START_TEST(test_remove)
{
	host_t *addr = host_create_from_string("127.0.0.1", 1024);
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();
	fail_unless(sad->insert(sad, 23, addr, addr, 42, 50),
				"Error inserting SAD entry");
	fail_unless(sad->get_esa_id(sad, addr, addr, 42, 50) == 23,
				"Error getting esa id");
	fail_unless(sad->remove(sad, 23),
				"Error removing SAD entry");
	fail_unless(sad->get_esa_id(sad, addr, addr, 42, 50) == 0,
				"Got esa id for removed SAD entry");
	sad->destroy(sad);
	addr->destroy(addr);
}
END_TEST

START_TEST(test_remove_nonexistent)
{
	tkm_kernel_sad_t *sad = tkm_kernel_sad_create();
	fail_if(sad->remove(sad, 1),
			"Expected error removing nonexistent SAD entry");
	sad->destroy(sad);
}
END_TEST

TCase *make_kernel_sad_tests(void)
{
	TCase *tc = tcase_create("Kernel SAD tests");
	tcase_add_test(tc, test_sad_creation);
	tcase_add_test(tc, test_insert);
	tcase_add_test(tc, test_insert_duplicate);
	tcase_add_test(tc, test_get_esa_id);
	tcase_add_test(tc, test_get_esa_id_nonexistent);
	tcase_add_test(tc, test_remove);
	tcase_add_test(tc, test_remove_nonexistent);

	return tc;
}
