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

#include <pthread.h>

/**
 * Failure message buf
 */
static char failure_buf[512];

/**
 * Source file failure occurred
 */
static const char *failure_file;

/**
 * Line of source file failure occurred
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
 * Main thread performing tests
 */
static pthread_t main_thread;

/**
 * Let test case fail
 */
static inline void test_failure()
{
	if (pthread_self() == main_thread)
	{
		siglongjmp(test_restore_point_env, 1);
	}
	else
	{
		pthread_kill(main_thread, SIGUSR1);
		/* how can we stop just the thread? longjmp to a restore point? */
	}
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
		case SIGUSR1:
			/* a different thread failed, abort test */
			return test_failure();
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
	/* unable to restore a valid context for that thread, terminate */
	fprintf(stderr, "\n%s(%d) outside of main thread:\n", signame, signal);
	failure_backtrace->log(failure_backtrace, stderr, TRUE);
	fprintf(stderr, "terminating...\n");
	abort();
}

/**
 * See header.
 */
void test_setup_handler()
{
	struct sigaction action = {
		.sa_handler = test_sighandler,
	};

	main_thread = pthread_self();

	/* signal handler inherited by all threads */
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	/* ignore ALRM/USR1, these are catched by main thread only */
	action.sa_handler = SIG_IGN;
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);
}

/**
 * See header.
 */
void test_setup_timeout(int s)
{
	struct sigaction action = {
		.sa_handler = test_sighandler,
	};

	/* This called by main thread only. Setup handler for timeout and
	 * failure cross-thread signaling. */
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);

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
