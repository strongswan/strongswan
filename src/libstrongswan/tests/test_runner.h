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

#ifndef TEST_RUNNER_H_
#define TEST_RUNNER_H_

#include <check.h>

Suite *bio_reader_suite_create();
Suite *bio_writer_suite_create();
Suite *chunk_suite_create();
Suite *enum_suite_create();
Suite *enumerator_suite_create();
Suite *linked_list_suite_create();
Suite *linked_list_enumerator_suite_create();
Suite *hashtable_suite_create();
Suite *array_suite_create();
Suite *identification_suite_create();
Suite *threading_suite_create();
Suite *utils_suite_create();
Suite *vectors_suite_create();
Suite *ecdsa_suite_create();
Suite *rsa_suite_create();
Suite *host_suite_create();
Suite *printf_suite_create();

#endif /** TEST_RUNNER_H_ */
