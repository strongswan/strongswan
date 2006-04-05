/**
 * @file thread_pool_test.h
 * 
 * @brief Tests for the thread_pool_t class.
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

#ifndef THREAD_POOL_TEST_H_
#define THREAD_POOL_TEST_H_

#include <utils/tester.h>

/**
 * @brief Test function for the class thread_pool_t.
 * 
 * @param tester 	tester object
 * 
 * @ingroup testcases
 */
void test_thread_pool(protected_tester_t *tester);

#endif /*THREAD_POOL_TEST_H_*/
