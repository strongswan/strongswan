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

#include <signal.h>
#include <unistd.h>

/**
 * Failure message buf
 */
static char failure_buf[512];

/**
 * Source file failure occured
 */
static const char *failure_file;

/**
 * Line of source file failure occured
 */
static int failure_line;

/**
 * Backtrace of failure, if any
 */
static backtrace_t *failure_backtrace;

/**
 * Longjump restore point when failing
 */
sigjmp_buf test_restore_point_env;

/**
 * See header.
 */
test_suite_t* test_suite_create(const char *name)
{
	test_suite_t *suite;

	INIT(suite,
		.name = name,
		.tcases = array_create(0, 0),
	);
	return suite;
}

/**
 * See header.
 */
test_case_t* test_case_create(const char *name)
{
	test_case_t *tcase;

	INIT(tcase,
		.name = name,
		.functions = array_create(sizeof(test_function_t), 0),
		.fixtures = array_create(sizeof(test_fixture_t), 0),
		.timeout = TEST_FUNCTION_DEFAULT_TIMEOUT,
	);
	return tcase;
}

/**
 * See header.
 */
void test_case_add_checked_fixture(test_case_t *tcase, test_fixture_cb_t setup,
								   test_fixture_cb_t teardown)
{
	test_fixture_t fixture = {
		.setup = setup,
		.teardown = teardown,
	};
	array_insert(tcase->fixtures, -1, &fixture);
}

/**
 * See header.
 */
void test_case_add_test_name(test_case_t *tcase, char *name,
							 test_function_cb_t cb, int start, int end)
{
	test_function_t fun = {
		.name = name,
		.cb = cb,
		.start = start,
		.end = end,
	};
	array_insert(tcase->functions, -1, &fun);
}

/**
 * See header.
 */
void test_case_set_timeout(test_case_t *tcase, int s)
{
	tcase->timeout = s;
}

/**
 * See header.
 */
void test_suite_add_case(test_suite_t *suite, test_case_t *tcase)
{
	array_insert(suite->tcases, -1, tcase);
}

/**
 * Let test case fail
 */
static inline void test_failure()
{
	siglongjmp(test_restore_point_env, 1);
}

/**
 * See header.
 */
void test_fail_vmsg(const char *file, int line, char *fmt, va_list args)
{
	vsnprintf(failure_buf, sizeof(failure_buf), fmt, args);
	failure_line = line;
	failure_file = file;

	test_failure();
}

/**
 * See header.
 */
void test_fail_msg(const char *file, int line, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(failure_buf, sizeof(failure_buf), fmt, args);
	failure_line = line;
	failure_file = file;
	va_end(args);

	test_failure();
}

/**
 * Signal handler catching critical and alarm signals
 */
static void test_sighandler(int signal)
{
	char *signame;
	bool old = FALSE;

	switch (signal)
	{
		case SIGSEGV:
			signame = "SIGSEGV";
			break;
		case SIGILL:
			signame = "SIGILL";
			break;
		case SIGBUS:
			signame = "SIGBUS";
			break;
		case SIGALRM:
			signame = "timeout";
			break;
		default:
			signame = "SIG";
			break;
	}
	if (lib->leak_detective)
	{
		old = lib->leak_detective->set_state(lib->leak_detective, FALSE);
	}
	failure_backtrace = backtrace_create(3);
	if (lib->leak_detective)
	{
		lib->leak_detective->set_state(lib->leak_detective, old);
	}
	test_fail_msg(NULL, 0, "%s(%d)", signame, signal);
}

/**
 * See header.
 */
void test_setup_handler()
{
	struct sigaction action;

	action.sa_handler = test_sighandler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGALRM, &action, NULL);
}

/**
 * See header.
 */
void test_setup_timeout(int s)
{
	alarm(s);
}

/**
 * See header.
 */
int test_failure_get(char *msg, int len, const char **file)
{
	strncpy(msg, failure_buf, len - 1);
	msg[len - 1] = 0;
	*file = failure_file;
	return failure_line;
}

/**
 * See header.
 */
backtrace_t *test_failure_backtrace()
{
	backtrace_t *bt;

	bt = failure_backtrace;
	failure_backtrace = NULL;

	return bt;
}
