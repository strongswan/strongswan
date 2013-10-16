/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

#include "test_runner.h"

#include <library.h>
#include <plugins/plugin_feature.h>
#include <collections/array.h>

#include <dirent.h>
#include <unistd.h>
#include <limits.h>

/**
 * Get a tty color escape character for stderr
 */
#define TTY(color) tty_escape_get(2, TTY_FG_##color)

/**
 * Load plugins from builddir
 */
static bool load_plugins()
{
	enumerator_t *enumerator;
	char *name, path[PATH_MAX], dir[64];

	enumerator = enumerator_create_token(PLUGINS, " ", "");
	while (enumerator->enumerate(enumerator, &name))
	{
		snprintf(dir, sizeof(dir), "%s", name);
		translate(dir, "-", "_");
		snprintf(path, sizeof(path), "%s/%s/.libs", PLUGINDIR, dir);
		lib->plugins->add_path(lib->plugins, path);
	}
	enumerator->destroy(enumerator);

	return lib->plugins->load(lib->plugins, PLUGINS);
}

/**
 * Check if a specific feature is available, return falg if so
 */
static int check_feature(plugin_feature_t feature, int flag)
{
	if (lib->plugins->has_feature(lib->plugins, feature))
	{
		return flag;
	}
	return 0;
}

/**
 * Load all available test suites
 */
static array_t *load_suites()
{
	array_t *suites;
	enum {
		OTEST_RSA = (1<<0),
		OTEST_ECDSA = (1<<1),
	} otest = 0;

	library_init(NULL);
	if (!load_plugins())
	{
		library_deinit();
		return NULL;
	}
	lib->plugins->status(lib->plugins, LEVEL_CTRL);

	/* we have to build the test suite array without leak detective, so
	 * separate plugin checks and suite creation */
	otest |= check_feature(PLUGIN_DEPENDS(PRIVKEY_GEN, KEY_RSA), OTEST_RSA);
	otest |= check_feature(PLUGIN_DEPENDS(PRIVKEY_GEN, KEY_ECDSA), OTEST_ECDSA);

	library_deinit();

	suites = array_create(0, 0);

	array_insert(suites, -1, bio_reader_suite_create());
	array_insert(suites, -1, bio_writer_suite_create());
	array_insert(suites, -1, chunk_suite_create());
	array_insert(suites, -1, enum_suite_create());
	array_insert(suites, -1, enumerator_suite_create());
	array_insert(suites, -1, linked_list_suite_create());
	array_insert(suites, -1, linked_list_enumerator_suite_create());
	array_insert(suites, -1, hashtable_suite_create());
	array_insert(suites, -1, array_suite_create());
	array_insert(suites, -1, identification_suite_create());
	array_insert(suites, -1, threading_suite_create());
	array_insert(suites, -1, utils_suite_create());
	array_insert(suites, -1, host_suite_create());
	array_insert(suites, -1, vectors_suite_create());
	array_insert(suites, -1, pen_suite_create());
	array_insert(suites, -1, asn1_suite_create());
	array_insert(suites, -1, printf_suite_create());
	if (otest & OTEST_RSA)
	{
		array_insert(suites, -1, rsa_suite_create());
	}
	if (otest & OTEST_ECDSA)
	{
		array_insert(suites, -1, ecdsa_suite_create());
	}

	return suites;
}

/**
 * Unload and destroy test suites and associated data
 */
static void unload_suites(array_t *suites)
{
	test_suite_t *suite;
	test_case_t *tcase;

	while (array_remove(suites, 0, &suite))
	{
		while (array_remove(suite->tcases, 0, &tcase))
		{
			array_destroy(tcase->functions);
			array_destroy(tcase->fixtures);
		}
		free(suite);
	}
	array_destroy(suites);
}

/**
 * Run a single test function, return FALSE on failure
 */
static bool run_test(test_function_t *tfun, int i)
{
	if (test_restore_point())
	{
		tfun->cb(i);
		return TRUE;
	}
	return FALSE;
}

/**
 * Invoke fixture setup/teardown
 */
static bool call_fixture(test_case_t *tcase, bool up)
{
	enumerator_t *enumerator;
	test_fixture_t *fixture;
	bool failure = FALSE;

	enumerator = array_create_enumerator(tcase->fixtures);
	while (enumerator->enumerate(enumerator, &fixture))
	{
		if (test_restore_point())
		{
			if (up)
			{
				fixture->setup();
			}
			else
			{
				fixture->teardown();
			}
		}
		else
		{
			failure = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return !failure;
}

/**
 * Test initialization, initializes libstrongswan for the next run
 */
static bool pre_test()
{
	library_init(NULL);

	/* use non-blocking RNG to generate keys fast */
	lib->settings->set_default_str(lib->settings,
			"libstrongswan.plugins.random.random",
			lib->settings->get_str(lib->settings,
				"libstrongswan.plugins.random.urandom", "/dev/urandom"));

	if (lib->leak_detective)
	{
		/* disable leak reports during testing */
		lib->leak_detective->set_report_cb(lib->leak_detective,
										   NULL, NULL, NULL);
	}
	if (!load_plugins())
	{
		library_deinit();
		return FALSE;
	}

	dbg_default_set_level(LEVEL_SILENT);
	return TRUE;
}

/**
 * Failure description
 */
typedef struct {
	char *name;
	char msg[512 - sizeof(char*) - 2 * sizeof(int)];
	const char *file;
	int line;
	int i;
	backtrace_t *bt;
} failure_t;

/**
 * Data passed to leak report callbacks
 */
typedef struct {
	array_t *failures;
	char *name;
	int i;
	int leaks;
} report_data_t;

/**
 * Leak report callback, build failures from leaks
 */
static void report_leaks(report_data_t *data, int count, size_t bytes,
						 backtrace_t *bt, bool detailed)
{
	failure_t failure = {
		.name = data->name,
		.i = data->i,
		.bt = bt->clone(bt),
	};

	snprintf(failure.msg, sizeof(failure.msg),
			 "Leak detected: %d allocations using %zu bytes", count, bytes);

	array_insert(data->failures, -1, &failure);
}

/**
 * Leak summary callback, check if any leaks found
 */
static void sum_leaks(report_data_t *data, int count, size_t bytes,
					  int whitelisted)
{
	data->leaks = count;
}

/**
 * Do library cleanup and optionally check for memory leaks
 */
static bool post_test(bool check_leaks, array_t *failures, char *name, int i)
{
	report_data_t data = {
		.failures = failures,
		.name = name,
		.i = i,
	};

	if (check_leaks && lib->leak_detective)
	{
		lib->leak_detective->set_report_cb(lib->leak_detective,
								(leak_detective_report_cb_t)report_leaks,
								(leak_detective_summary_cb_t)sum_leaks, &data);
	}
	library_deinit();

	return data.leaks != 0;
}

/**
 * Collect failure information, add failure_t to array
 */
static void collect_failure_info(array_t *failures, char *name, int i)
{
	failure_t failure = {
		.name = name,
		.i = i,
		.bt = test_failure_backtrace(),
	};

	failure.line = test_failure_get(failure.msg, sizeof(failure.msg),
									&failure.file);

	array_insert(failures, -1, &failure);
}

/**
 * Print array of collected failure_t to stderr
 */
static void print_failures(array_t *failures)
{
	failure_t failure;

	backtrace_init();

	while (array_remove(failures, 0, &failure))
	{
		fprintf(stderr, "      %sFailure in '%s': %s (",
				TTY(RED), failure.name, failure.msg);
		if (failure.line)
		{
			fprintf(stderr, "%s:%d, ", failure.file, failure.line);
		}
		fprintf(stderr, "i = %d)%s\n", failure.i, TTY(DEF));
		if (failure.bt)
		{
			failure.bt->log(failure.bt, stderr, TRUE);
			failure.bt->destroy(failure.bt);
		}
	}

	backtrace_deinit();
}

/**
 * Run a single test case with fixtures
 */
static bool run_case(test_case_t *tcase)
{
	enumerator_t *enumerator;
	test_function_t *tfun;
	int passed = 0;
	array_t *failures;

	failures = array_create(sizeof(failure_t), 0);

	fprintf(stderr, "    Running case '%s': ", tcase->name);
	fflush(stderr);

	enumerator = array_create_enumerator(tcase->functions);
	while (enumerator->enumerate(enumerator, &tfun))
	{
		int i, rounds = 0;

		for (i = tfun->start; i < tfun->end; i++)
		{
			if (pre_test())
			{
				bool ok = FALSE, leaks = FALSE;

				test_setup_timeout(tcase->timeout);

				if (call_fixture(tcase, TRUE))
				{
					if (run_test(tfun, i))
					{
						if (call_fixture(tcase, FALSE))
						{
							ok = TRUE;
						}
					}
					else
					{
						call_fixture(tcase, FALSE);
					}

				}
				leaks = post_test(ok, failures, tfun->name, i);

				test_setup_timeout(0);

				if (ok)
				{
					if (!leaks)
					{
						rounds++;
						fprintf(stderr, "%s+%s", TTY(GREEN), TTY(DEF));
					}
				}
				else
				{
					collect_failure_info(failures, tfun->name, i);
				}
				if (!ok || leaks)
				{
					fprintf(stderr, "%s-%s", TTY(RED), TTY(DEF));
				}
			}
			else
			{
				fprintf(stderr, "!");
			}
		}
		fflush(stderr);
		if (rounds == tfun->end - tfun->start)
		{
			passed++;
		}
	}
	enumerator->destroy(enumerator);

	fprintf(stderr, "\n");

	print_failures(failures);
	array_destroy(failures);

	return passed == array_count(tcase->functions);
}

/**
 * Run a single test suite
 */
static bool run_suite(test_suite_t *suite)
{
	enumerator_t *enumerator;
	test_case_t *tcase;
	int passed = 0;

	fprintf(stderr, "  Running suite '%s':\n", suite->name);

	enumerator = array_create_enumerator(suite->tcases);
	while (enumerator->enumerate(enumerator, &tcase))
	{
		if (run_case(tcase))
		{
			passed++;
		}
	}
	enumerator->destroy(enumerator);

	if (passed == array_count(suite->tcases))
	{
		fprintf(stderr, "  %sPassed all %u '%s' test cases%s\n",
				TTY(GREEN), array_count(suite->tcases), suite->name, TTY(DEF));
		return TRUE;
	}
	fprintf(stderr, "  %sPassed %u/%u '%s' test cases%s\n",
			TTY(RED), passed, array_count(suite->tcases), suite->name, TTY(DEF));
	return FALSE;
}

int main(int argc, char *argv[])
{
	array_t *suites;
	test_suite_t *suite;
	enumerator_t *enumerator;
	int passed = 0, result;

	/* redirect all output to stderr (to redirect make's stdout to /dev/null) */
	dup2(2, 1);

	test_setup_handler();

	suites = load_suites();
	if (!suites)
	{
		return EXIT_FAILURE;
	}

	fprintf(stderr, "Running %u test suites:\n", array_count(suites));

	enumerator = array_create_enumerator(suites);
	while (enumerator->enumerate(enumerator, &suite))
	{
		if (run_suite(suite))
		{
			passed++;
		}
	}
	enumerator->destroy(enumerator);

	if (passed == array_count(suites))
	{
		fprintf(stderr, "%sPassed all %u suites%s\n",
				TTY(GREEN), array_count(suites), TTY(DEF));
		result = EXIT_SUCCESS;
	}
	else
	{
		fprintf(stderr, "%sPassed %u of %u suites%s\n",
				TTY(RED), passed, array_count(suites), TTY(DEF));
		result = EXIT_FAILURE;
	}

	unload_suites(suites);

	return result;
}
