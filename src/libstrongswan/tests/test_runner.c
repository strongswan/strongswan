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

#include <unistd.h>

#include "test_runner.h"

#include <library.h>

int main()
{
	SRunner *sr;
	int nf;

	/* if a test fails there is no cleanup, so disable leak detective */
	setenv("LEAK_DETECTIVE_DISABLE", "1", 1);
	/* redirect all output to stderr (to redirect make's stdout to /dev/null) */
	dup2(2, 1);

	library_init(NULL);

	sr = srunner_create(NULL);
	srunner_add_suite(sr, chunk_suite_create());
	srunner_add_suite(sr, enum_suite_create());
	srunner_add_suite(sr, enumerator_suite_create());
	srunner_add_suite(sr, linked_list_suite_create());
	srunner_add_suite(sr, linked_list_enumerator_suite_create());
	srunner_add_suite(sr, hashtable_suite_create());
	srunner_add_suite(sr, identification_suite_create());
	srunner_add_suite(sr, threading_suite_create());
	srunner_add_suite(sr, utils_suite_create());

	srunner_run_all(sr, CK_NORMAL);
	nf = srunner_ntests_failed(sr);

	srunner_free(sr);
	library_deinit();

	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
