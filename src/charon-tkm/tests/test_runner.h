/*
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

TCase *make_id_manager_tests(void);
TCase *make_chunk_map_tests(void);
TCase *make_utility_tests(void);
TCase *make_nonceg_tests(void);
TCase *make_diffie_hellman_tests(void);
TCase *make_keymat_tests(void);
TCase *make_kernel_sad_tests(void);

#endif /** TEST_RUNNER_H_ */
