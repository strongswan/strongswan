/**
 * @file thread_pool_test.c
 * 
 * @brief Tests to test the Thread-Pool type thread_pool_t
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

#include <stdlib.h>

#include "thread_pool_test.h"

#include <threads/thread_pool.h>

/*
 * Description in header file
 */
void test_thread_pool(tester_t *tester)
{
	size_t desired_pool_size = 10;
	size_t pool_size;
	
	thread_pool_t *pool = thread_pool_create(desired_pool_size);
	pool_size = pool->get_pool_size(pool);
	tester->assert_true(tester, (desired_pool_size == pool_size), "thread creation");
	pool->destroy(pool);
}
