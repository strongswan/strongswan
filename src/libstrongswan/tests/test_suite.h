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

#ifndef TEST_UTILS_H_
#define TEST_UTILS_H_

#include <check.h>
#include <library.h>
#include <utils/debug.h>

/**
 * Used to mark test cases that use test fixtures.
 */
#define UNIT_TEST_FIXTURE_USED "UNIT_TEST_FIXTURE_USED"

/**
 * Check for memory leaks and fail if any are encountered.
 */
#define CHECK_FOR_LEAKS() do \
{ \
	if (lib->leak_detective) \
	{ \
		if (lib->leak_detective->leaks(lib->leak_detective)) { \
			lib->leak_detective->report(lib->leak_detective, TRUE); \
		} \
		ck_assert_int_eq(lib->leak_detective->leaks(lib->leak_detective), 0); \
	} \
} \
while(0)

/**
 * Extended versions of the START|END_TEST macros that use leak detective.
 *
 * Since each test case runs in its own fork of the test runner the stuff
 * allocated before the test starts is not freed, so leak detective is disabled
 * by default to prevent false positives.  By enabling it right when the test
 * starts we at least capture leaks created by the tested objects/functions and
 * the test case itself.  This allows writing test cases for cleanup functions.
 *
 * To define test fixture with possibly allocated/destroyed memory that is
 * allocated/freed in a test case use the START|END_SETUP|TEARDOWN macros.
 */
#undef START_TEST
#define START_TEST(name) \
static void name (int _i CK_ATTRIBUTE_UNUSED) \
{ \
	tcase_fn_start(""#name, __FILE__, __LINE__); \
	dbg_default_set_level(LEVEL_SILENT); \
	if (lib->leak_detective) \
	{ \
		lib->leak_detective->set_state(lib->leak_detective, TRUE); \
	}

#undef END_TEST
#define END_TEST \
	if (!lib->get(lib, UNIT_TEST_FIXTURE_USED)) \
	{ \
		CHECK_FOR_LEAKS(); \
	} \
}

/**
 * Define a function to setup a test fixture that can be used with the above
 * macros.
 */
#define START_SETUP(name) \
static void name() \
{ \
	lib->set(lib, UNIT_TEST_FIXTURE_USED, (void*)TRUE); \
	if (lib->leak_detective) \
	{ \
		lib->leak_detective->set_state(lib->leak_detective, TRUE); \
	}

/**
 * End a setup function
 */
#define END_SETUP }

/**
 * Define a function to teardown a test fixture that can be used with the above
 * macros.
 */
#define START_TEARDOWN(name) \
static void name() \
{

/**
 * End a teardown function
 */
#define END_TEARDOWN \
	if (lib->get(lib, UNIT_TEST_FIXTURE_USED)) \
	{ \
		CHECK_FOR_LEAKS(); \
	} \
}

#endif /** TEST_UTILS_H_ */
