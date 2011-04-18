/*
 * Copyright (C) 2007 Martin Willi
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

#include "unit_tester.h"

#include <daemon.h>

typedef struct private_unit_tester_t private_unit_tester_t;
typedef struct unit_test_t unit_test_t;
typedef enum test_status_t test_status_t;

/**
 * private data of unit_tester
 */
struct private_unit_tester_t {

	/**
	 * public functions
	 */
	unit_tester_t public;
};

struct unit_test_t {

	/**
	 * name of the test
	 */
	char *name;

	/**
	 * test function
	 */
	bool (*test)(void);

	/**
	 * run the test?
	 */
	bool enabled;
};

#undef DEFINE_TEST
#define DEFINE_TEST(name, function, enabled) bool function();
#include <plugins/unit_tester/tests.h>
#undef DEFINE_TEST
#define DEFINE_TEST(name, function, enabled) {name, function, enabled},
static unit_test_t tests[] = {
#include <plugins/unit_tester/tests.h>
};

static void run_tests(private_unit_tester_t *this)
{
	int i, run = 0, failed = 0, success = 0, skipped = 0;

	DBG1(DBG_CFG, "running unit tests, %d tests registered",
		 sizeof(tests)/sizeof(unit_test_t));

	for (i = 0; i < sizeof(tests)/sizeof(unit_test_t); i++)
	{
		if (tests[i].enabled)
		{
			run++;
			if (tests[i].test())
			{
				DBG1(DBG_CFG, "test '%s' successful", tests[i].name);
				success++;
			}
			else
			{
				DBG1(DBG_CFG, "test '%s' failed", tests[i].name);
				failed++;
			}
		}
		else
		{
			DBG1(DBG_CFG, "test '%s' disabled", tests[i].name);
			skipped++;
		}
	}
	DBG1(DBG_CFG, "%d/%d tests successful (%d failed, %d disabled)",
		 success, run, failed, skipped);
}

METHOD(plugin_t, get_name, char*,
	private_unit_tester_t *this)
{
	return "unit-tester";
}

METHOD(plugin_t, destroy, void,
	private_unit_tester_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *unit_tester_plugin_create()
{
	private_unit_tester_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
	);

	run_tests(this);

	return &this->public.plugin;
}

