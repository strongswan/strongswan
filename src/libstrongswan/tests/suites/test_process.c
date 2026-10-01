/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2014 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#include <unistd.h>
#include <fcntl.h>

#include <utils/process.h>

START_TEST(test_retval_true)
{
	process_t *process;
	char *argv[] = {
#ifdef WIN32
		"C:\\Windows\\system32\\cmd.exe",
		"/C",
		"exit 0",
#else
		"/bin/sh",
		"-c",
		"true",
#endif
		NULL
	};
	int retval;

	process = process_start(argv, NULL, NULL, NULL, NULL, TRUE);
	ck_assert(process != NULL);
	ck_assert(process->wait(process, &retval));
	ck_assert_int_eq(retval, 0);
}
END_TEST

START_TEST(test_retval_false)
{
	process_t *process;
	char *argv[] = {
#ifdef WIN32
		"C:\\Windows\\system32\\cmd.exe",
		"/C",
		"exit 1",
#else
		"/bin/sh",
		"-c",
		"false",
#endif
		NULL
	};
	int retval;

	process = process_start(argv, NULL, NULL, NULL, NULL, TRUE);
	ck_assert(process != NULL);
	ck_assert(process->wait(process, &retval));
	ck_assert(retval != 0);
}
END_TEST

START_TEST(test_not_found)
{
	process_t *process;
	char *argv[] = {
		"/bin/does-not-exist",
		NULL
	};
	int retval;

	process = process_start(argv, NULL, NULL, NULL, NULL, TRUE);
	/* both is acceptable behavior, posix_spawn() might fail with 127 */
	ck_assert(process == NULL || !process->wait(process, &retval) ||
			  retval == 127);
}
END_TEST

START_TEST(test_echo)
{
	process_t *process;
	char *argv[] = {
#ifdef WIN32
		"C:\\Windows\\system32\\more.com",
#else
		"/bin/sh",
		"-c",
		"cat",
#endif
		NULL
	};
	int retval, in, out;
	char *msg = "test";
	char buf[strlen(msg) + 1];
	bool close_all = _i;

	memset(buf, 0, strlen(msg) + 1);

	process = process_start(argv, NULL, &in, &out, NULL, close_all);
	ck_assert(process != NULL);
	ck_assert_int_eq(write(in, msg, strlen(msg)), strlen(msg));
	ck_assert(close(in) == 0);
	ck_assert_int_eq(read(out, buf, strlen(msg) + 1), strlen(msg));
	ck_assert_str_eq(buf, msg);
	ck_assert(close(out) == 0);
	ck_assert(process->wait(process, &retval));
	ck_assert_int_eq(retval, 0);
}
END_TEST

START_TEST(test_echo_err)
{
	process_t *process;
	char *argv[] = {
#ifdef WIN32
		"C:\\Windows\\system32\\cmd.exe",
		"/C",
		"1>&2 C:\\Windows\\system32\\more.com",
#else
		"/bin/sh",
		"-c",
		"1>&2 cat",
#endif
		NULL
	};
	int retval, in, err;
	char *msg = "a longer test message";
	char buf[strlen(msg) + 1];
	bool close_all = _i;

	memset(buf, 0, strlen(msg) + 1);

	process = process_start(argv, NULL, &in, NULL, &err, close_all);
	ck_assert(process != NULL);
	ck_assert_int_eq(write(in, msg, strlen(msg)), strlen(msg));
	ck_assert(close(in) == 0);
	ck_assert_int_eq(read(err, buf, strlen(msg) + 1), strlen(msg));
	ck_assert_str_eq(buf, msg);
	ck_assert(close(err) == 0);
	ck_assert(process->wait(process, &retval));
	ck_assert_int_eq(retval, 0);
}
END_TEST

START_TEST(test_close_all)
{
#ifndef WIN32
	process_t *process;
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };
	int extra, err, code;
	char cmd[64], fd_file[64], buf[BUF_LEN];
	bool close_all = _i;

	/* extra fd above 2, deliberately without O_CLOEXEC so the child inherits it
	 * unless close_all closes it */
	extra = open("/dev/null", O_RDONLY);
	ck_assert(extra >= 3);

	/* because many shells (e.g. dash) only support single digits for shell
	 * redirection, we only use this portable approach if the fd fits */
	if (extra <= 9)
	{
		snprintf(cmd, sizeof(cmd), "true <&%d", extra);
	}
	else
	{
		/* otherwise we try to test the existence of the fd via /dev or /proc
		 * file system.  however, this is not fully portable as e.g. FreeBSD
		 * needs fdescfs mounted for /dev/fd populated with fds > 2 and /proc
		 * is technically also optional on Linux, so we do a pre-check in the
		 * parent where the fd must exist in one of these locations */
		snprintf(fd_file, sizeof(fd_file), "/dev/fd/%d", extra);
		if (access(fd_file, F_OK) != 0)
		{
			snprintf(fd_file, sizeof(fd_file), "/proc/self/fd/%d", extra);
			if (access(fd_file, F_OK) != 0)
			{
				close(extra);
				fail("neither /dev/fd/%d nor /proc/self/fd/%d available, "
					 "cannot verify close_all", extra, extra);
				return;
			}
		}
		snprintf(cmd, sizeof(cmd), "test -e %s", fd_file);
	}
	argv[2] = cmd;

	process = process_start(argv, NULL, NULL, NULL, &err, close_all);
	ck_assert(process != NULL);
	/* drain stderr */
	ignore_result(read(err, buf, sizeof(buf)));
	close(err);
	ck_assert(process->wait(process, &code));
	if (close_all)
	{	/* fd must be gone: redirection or check fails, sh exits non-zero */
		ck_assert(code != 0);
	}
	else
	{	/* fd must survive: redirection or check succeeds, exit 0 */
		ck_assert_int_eq(code, 0);
	}
	close(extra);
#endif
}
END_TEST

START_TEST(test_env)
{
	process_t *process;
	char *argv[] = {
#ifdef WIN32
		"C:\\Windows\\system32\\cmd.exe",
		"/C",
		"echo %A% %B%",
#else
		"/bin/sh",
		"-c",
		"/bin/echo -n $A $B",
#endif
		NULL
	};
	char *envp[] = {
		"A=atest",
		"B=bstring",
		NULL
	};
	int retval, out;
	char buf[64] = {};

	process = process_start(argv, envp, NULL, &out, NULL, TRUE);
	ck_assert(process != NULL);
	ck_assert(read(out, buf, sizeof(buf)) > 0);
#ifdef WIN32
	ck_assert_str_eq(buf, "atest bstring\r\n");
#else
	ck_assert_str_eq(buf, "atest bstring");
#endif
	ck_assert(close(out) == 0);
	ck_assert(process->wait(process, &retval));
	ck_assert_int_eq(retval, 0);
}
END_TEST

START_TEST(test_shell)
{
	process_t *process;
	int retval;

	process = process_start_shell(NULL, NULL, NULL, NULL, "exit %d", 3);
	ck_assert(process != NULL);
	ck_assert(process->wait(process, &retval));
	ck_assert_int_eq(retval, 3);
}
END_TEST

Suite *process_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("process");

	tc = tcase_create("return values");
	tcase_set_timeout(tc, 10);
	tcase_add_test(tc, test_retval_true);
	tcase_add_test(tc, test_retval_false);
	suite_add_tcase(s, tc);

	tc = tcase_create("not found");
	tcase_set_timeout(tc, 10);
	tcase_add_test(tc, test_not_found);
	suite_add_tcase(s, tc);

	tc = tcase_create("echo");
	tcase_set_timeout(tc, 10);
	tcase_add_loop_test(tc, test_echo, 0, 2);
	tcase_add_loop_test(tc, test_echo_err, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("close_all");
	tcase_set_timeout(tc, 10);
	tcase_add_loop_test(tc, test_close_all, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("env");
	tcase_set_timeout(tc, 10);
	tcase_add_test(tc, test_env);
	suite_add_tcase(s, tc);

	tc = tcase_create("shell");
	tcase_set_timeout(tc, 10);
	tcase_add_test(tc, test_shell);
	suite_add_tcase(s, tc);

	return s;
}
