/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
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

#include <plugins/plugin_feature.h>

typedef struct test_configuration_t test_configuration_t;

/**
 * Test configuration, suite constructor with plugin dependency
 */
struct test_configuration_t {

	/**
	 * Constructor function to create suite.
	 */
	test_suite_t *(*suite)();

	/**
	 * Plugin feature this test suite depends on
	 */
	plugin_feature_t feature;
};

/**
 * Run test configuration, loading plugins from plugin base directory.
 *
 * Both the configs and the plugindirs array must be terminated with a NULL
 * element.
 *
 * @param configs		test suite constructors with dependencies
 * @param plugindirs	base directories containing plugin directories to load
 * @param plugins		plugin names to load, space separated
 * @return				test result, EXIT_SUCCESS if all tests passed
 */
int test_runner_run(test_configuration_t config[],
					char *plugindirs[], char *plugins);
