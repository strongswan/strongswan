/**
 * @file hasher_test.h
 * 
 * @brief Tests for the hasher_t classes.
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
 
#ifndef HASHER_TEST_H_
#define HASHER_TEST_H_

#include <crypto/hashers/hasher.h>
#include <crypto/hashers/md5_hasher.h>
#include <crypto/hashers/sha1_hasher.h>
#include <utils/tester.h>

/**
 * @brief Test function used to test the SHA1-hasher functionality.
 *
 * @param tester associated tester object
 * 
 * @ingroup testcases
 */
void test_sha1_hasher(protected_tester_t *tester);

/**
 * @brief Test function used to test the Md5-hasher functionality.
 *
 * @param tester associated tester object
 * 
 * @ingroup testcases
 */
void test_md5_hasher(protected_tester_t *tester);

#endif /*HASHER_TEST_H_*/
