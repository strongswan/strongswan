/**
 * @file hasher_sha1_test.h
 * 
 * @brief Tests the sha1 hasher 
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
 
#ifndef HASHER_SHA1_TEST_H_
#define HASHER_SHA1_TEST_H_

#include <transforms/hashers/hasher.h>
#include <transforms/hashers/hasher_sha1.h>
#include <utils/tester.h>

/**
 * @brief Test function used to test the sha1-hasher functionality
 *
 * @param tester associated tester object
 */
void test_hasher_sha1(tester_t *tester);

#endif /*HASHER_SHA1_TEST_H_*/
