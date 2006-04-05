/**
 * @file prf_plus_test.h
 * 
 * @brief Tests for the prf_plus_t class.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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
 
#ifndef PRF_PLUS_TEST_H_
#define PRF_PLUS_TEST_H_

#include <crypto/prf_plus.h>
#include <utils/tester.h>

/**
 * @brief Test function used to test the prf_plus class.
 *
 * @param tester 	associated tester object
 * 
 * @ingroup testcases
 */
void test_prf_plus(protected_tester_t *tester);

#endif /*PRF_PLUS_TEST_H_*/
