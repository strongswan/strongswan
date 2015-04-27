/*
 * Copyright (C) 2014 Tobias Brunner
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

#include <test_runner.h>
#include <hydra.h>

/* declare test suite constructors */
#define TEST_SUITE(x) test_suite_t* x();
#define TEST_SUITE_DEPEND(x, ...) TEST_SUITE(x)
#include "hydra_tests.h"
#undef TEST_SUITE
#undef TEST_SUITE_DEPEND

static test_configuration_t tests[] = {
#define TEST_SUITE(x) \
	{ .suite = x, },
#define TEST_SUITE_DEPEND(x, type, ...) \
	{ .suite = x, .feature = PLUGIN_DEPENDS(type, __VA_ARGS__) },
#include "hydra_tests.h"
	{ .suite = NULL, }
};

static bool test_runner_init(bool init)
{
	if (init)
	{
		libhydra_init();
	}
	else
	{
		lib->processor->set_threads(lib->processor, 0);
		lib->processor->cancel(lib->processor);
		libhydra_deinit();
	}
	return TRUE;
}

int main(int argc, char *argv[])
{
	return test_runner_run("libhydra", tests, test_runner_init);
}
