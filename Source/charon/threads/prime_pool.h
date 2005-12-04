/**
 * @file prime_pool.h
 *
 * @brief Interface of prime_pool_t.
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

#ifndef PRIME_POOL_H_
#define PRIME_POOL_H_

#include <gmp.h>

#include <types.h>
#include <network/packet.h>


typedef struct prime_pool_t prime_pool_t;

/**
 * @brief Prime generation thread.
 * 
 * Starts a low-priority thread which will
 * preallocate primes in the background.
 * This increases responsibility, since prime generation
 * is the most time-consuming task.
 * 
 * @ingroup threads
 */
struct prime_pool_t {

	/**
	 * @brief Get the number of available primes for the given prime size.
	 *
	 * @param prime_pool_t 	calling object
 	 * @param 				size of the prime
	 * @returns 			number of primes
	 */
	int (*get_count) (prime_pool_t *prime_pool, size_t prime_size);

	/**
	 * @brief Get a prime of the given size.
	 *
	 * If no primes are available, the threads generates one of its own.
	 * Supplied mpz will be initialized to a prime and must be cleared
	 * after usage.
	 *
	 * @param prime_pool_t 	calling object
	 * @return 				chunk containing the prime
	 */
	void (*get_prime) (prime_pool_t *prime_pool, size_t prime_size, mpz_t *prime);

	/**
	 * @brief Destroys a prime_pool object.
	 *
	 * Stopps the prime thread and destroys the pool.
	 *
	 * @param prime_pool_t 	calling object
	 */
	void (*destroy) (prime_pool_t *prime_pool);
};

/**
 * @brief Creates a prime pool with a thread in it.
 * 
 * The specified limit limits the preallocation of primes
 * for a specific prime_size. If limit is zero, no thread
 * will be created, prime computation is done from
 * the get_prime-calling thread.
 *
 * @param generation_limit	generation limit to use
 * @return 					created prime pool
 * 
 * @ingroup threads
 */
prime_pool_t *prime_pool_create(int generation_limit);

#endif /*PRIME_POOL_H_*/
