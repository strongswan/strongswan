/**
 * @file prime_pool_test.h
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

#include <string.h>
#include <unistd.h>
 
#include "prime_pool_test.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/logger.h>
#include <threads/prime_pool.h>


/* 
 * described in Header-File
 */
void test_prime_pool(protected_tester_t *tester)
{
	mpz_t p1, p2, p3, p4;
	prime_pool_t *prime_pool;
	
	prime_pool = prime_pool_create(20);
	
	prime_pool->get_prime(prime_pool, 4, &p1);
	sleep(1);
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 4) == 20, "number of  4 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 8) == 0, "number of  8 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 16) == 0, "number of 16 bytes primes");
	prime_pool->get_prime(prime_pool, 8, &p2);	
	sleep(1);
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 4) == 20, "number of  4 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 8) == 20, "number of  8 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 16) == 0, "number of 16 bytes primes");
	prime_pool->get_prime(prime_pool, 16, &p3);
	sleep(1);
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 4) == 20, "number of  4 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 8) == 20, "number of  8 bytes primes");
	tester->assert_true(tester, prime_pool->get_count(prime_pool, 16) == 20, "number of 16 bytes primes");
	prime_pool->get_prime(prime_pool, 16, &p4);
	
	mpz_clear(p1);
	mpz_clear(p2);
	mpz_clear(p3);
	mpz_clear(p4);
	prime_pool->destroy(prime_pool);
	
}
