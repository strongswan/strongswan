/**
 * @file prime_pool.c
 *
 * @brief Implementation of prime_pool_t.
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

#include <pthread.h>

#include "prime_pool.h"

#include <daemon.h>
#include <utils/allocator.h>
#include <utils/linked_list.h>
#include <utils/randomizer.h>


typedef struct prime_list_t prime_list_t;

/**
 * A prime_list_t contains prime values of a specific size.
 */
struct prime_list_t {
	/**
	 * Size of the stored primes .
	 */
	size_t prime_size;
	
	/**
	 * Is this much used prime_size ?
	 */
	u_int32_t usage;
	
	/**
	 * List of primes.
	 */
	linked_list_t *primes;
};

typedef struct private_prime_pool_t private_prime_pool_t;

 /**
 * @brief Private data of prime_pool_t.
 */
struct private_prime_pool_t {
	/**
	 * Public part of the prime_pool_t object.
	 */
 	prime_pool_t public;

	/**
	 * A list which contains a set of prime_list_t's.
	 */
	linked_list_t *prime_lists;

	/**
	 * prime generation is stopped if more than
	 * that primes of a kind are already generated.
	 */
	int generation_limit;
	
	/**
	 * Access to prime_lists is locked through this mutex.
	 */
	pthread_mutex_t mutex;

	/**
	 * If the queue is empty a thread has to wait
	 * This condvar is used to wake up such a thread.
	 */
	pthread_cond_t condvar;
	
	/**
	 * Prime generation thread.
	 */
	pthread_t thread;
	
	/** 
	 * Logger instance for the prime_pool.
	 */
	logger_t *logger;
	
	/**
	 * Function for the prime thread, generate primes.
	 */
	void (*generate_primes) (private_prime_pool_t *this);
	
	/**
	 * Calculate a prime of requested size.
	 */
	void (*compute_prime) (private_prime_pool_t *this, size_t prime_size, mpz_t *prime);
};


/**
 * Implementation of prime_pool_t.get_count.
 */
static int get_count(private_prime_pool_t *this, size_t prime_size)
{
	int count = 0;
	iterator_t *iterator;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->prime_lists->create_iterator(this->prime_lists, TRUE);
	while (iterator->has_next(iterator))
	{
		prime_list_t *prime_list;
		iterator->current(iterator, (void*)&prime_list);
		if (prime_list->prime_size == prime_size)
		{
			count = prime_list->primes->get_count(prime_list->primes);
			break;
		}
	}
	iterator->destroy(iterator);
	
	pthread_mutex_unlock(&(this->mutex));
	return count;
}

/**
 * Implementation of prime_pool_t.get_prime.
 */
static void get_prime(private_prime_pool_t *this, size_t prime_size, mpz_t *prime)
{
	bool prime_found = FALSE;
	iterator_t *iterator;
	bool create_new_list = TRUE;
	
	pthread_mutex_lock(&(this->mutex));
	
	iterator = this->prime_lists->create_iterator(this->prime_lists, TRUE);
	while (iterator->has_next(iterator))
	{
		prime_list_t *prime_list;
		iterator->current(iterator, (void*)&prime_list);
		/* decrease usage marker for every kind of prime */
		prime_list->usage = max(prime_list->usage - 1, 0);
		if (prime_list->prime_size == prime_size)
		{
			mpz_t *removed_prime;
			create_new_list = FALSE;
			/* this prime is well selling, increase usage marker by number of different prime sizes */
			prime_list->usage += this->prime_lists->get_count(this->prime_lists);
			if (prime_list->primes->remove_first(prime_list->primes, (void*)&removed_prime) == SUCCESS)
			{
				this->logger->log(this->logger, CONTROL|MOST, "Thread removed a prime with size %d", prime_size);
				mpz_init_set(*prime, *removed_prime);
				mpz_clear(*removed_prime);
				allocator_free(removed_prime);
				prime_found = TRUE;
			}
			/* wake up prime thread, he may be sleeping */
			pthread_cond_signal(&(this->condvar));
		}
	}
	iterator->destroy(iterator);
	
	if (create_new_list)
	{
		this->logger->log(this->logger, CONTROL|MORE, "Creating a new list for primes with size %d", prime_size);
		/* there is no list for this prime size, create one */
		prime_list_t *prime_list;
		prime_list = allocator_alloc_thing(prime_list_t);
		prime_list->usage = 1;
		prime_list->primes = linked_list_create();
		prime_list->prime_size = prime_size;
		this->prime_lists->insert_last(this->prime_lists, (void*)prime_list);
		/* wake up prime thread, he may be sleeping */
		pthread_cond_signal(&(this->condvar));
	}
	
	pthread_mutex_unlock(&(this->mutex));
	
	if (!prime_found)
	{
		/* no prime found, create one ourself */
		this->logger->log(this->logger, CONTROL|MOST, "Caller didn't find a prime, generates on it's own.");
		this->compute_prime(this, prime_size, prime);
	}
}

/**
 * Implementation of private_prime_pool_t.compute_prime.
 */
void compute_prime(private_prime_pool_t *this, size_t prime_size, mpz_t *prime)
{
	randomizer_t *randomizer;
	chunk_t random_bytes;
	
	randomizer = randomizer_create();
	mpz_init(*prime);
	
	do
	{
		/* TODO change to true random device ? */
		randomizer->allocate_pseudo_random_bytes(randomizer, prime_size, &random_bytes);
		
		/* make sure most significant bit is set */
		random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
		
		/* convert chunk to mpz value */
		mpz_import(*prime, random_bytes.len, 1, 1, 1, 0, random_bytes.ptr);

		/* get next prime */
		mpz_nextprime (*prime, *prime);

		allocator_free(random_bytes.ptr);
	}
	/* check if it isnt too large */
	while (((mpz_sizeinbase(*prime, 2) + 7) / 8) > prime_size);
	
	randomizer->destroy(randomizer);
}

/**
 * Implementation of private_prime_pool_t.generate_primes.
 */
void generate_primes(private_prime_pool_t *this)
{
	/* allow cancellation */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	while (TRUE)
	{
		prime_list_t *selected_prime_list = NULL;
		u_int32_t max_usage = 0;
		iterator_t *iterator;
		mpz_t *prime;
		
		
		this->logger->log(this->logger, CONTROL|MOST, "Finding most important prime size...");
		
		pthread_mutex_lock(&(this->mutex));
		
		/* get aprime to generate */
		iterator = this->prime_lists->create_iterator(this->prime_lists, TRUE);
		while (iterator->has_next(iterator))
		{
			prime_list_t *prime_list;
			iterator->current(iterator, (void*)&prime_list);
			this->logger->log(this->logger, CONTROL|MOST, "Primes with size %d have usage %d, %d in list",
								 prime_list->prime_size, prime_list->usage,
								 prime_list->primes->get_count(prime_list->primes));
			/* get the prime_size with the highest usage factor */
			if (prime_list->usage > max_usage)
			{
				if (prime_list->primes->get_count(prime_list->primes) < this->generation_limit)
				{
					/* there is work to do */
					max_usage = prime_list->usage;
					selected_prime_list = prime_list;
				}
			}
		}
		iterator->destroy(iterator);
		
		if (selected_prime_list == NULL)
		{		
			this->logger->log(this->logger, CONTROL|MORE, "Nothing to do, goint to sleep");
			/* nothing to do. wait, while able to cancel */
			pthread_cleanup_push((void(*)(void*))pthread_mutex_unlock, (void*)&(this->mutex));
			pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

			pthread_cond_wait(&(this->condvar), &(this->mutex));

			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			pthread_cleanup_pop(0);
		}
		
		pthread_mutex_unlock(&(this->mutex));
		
		if (selected_prime_list != NULL)
		{
			this->logger->log(this->logger, CONTROL|MORE, "Going to generate a prime with size %d",
								selected_prime_list->prime_size);
			/* generate the prime of requested size */
			prime = allocator_alloc_thing(mpz_t);
			compute_prime(this, selected_prime_list->prime_size, prime);
			
			/* insert prime */
			this->logger->log(this->logger, CONTROL|MOST, "Prime generated, inserting in list");
			pthread_mutex_lock(&(this->mutex));
			selected_prime_list->primes->insert_last(selected_prime_list->primes, (void*)prime);
			pthread_mutex_unlock(&(this->mutex));
		}
		/* abort if requested */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		pthread_testcancel();
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	}
}

 /**
 * Implementation of prime_pool_t.destroy.
 */
static void destroy (private_prime_pool_t *this)
{	
	/* cancel thread, if available */
	if (this->generation_limit > 0)
	{
		pthread_cancel(this->thread);
		pthread_join(this->thread, NULL);
	}
	/* get every prime list */
	while ((this->prime_lists->get_count(this->prime_lists) > 0))
	{
		prime_list_t *prime_list;
		
		this->prime_lists->remove_last(this->prime_lists, (void*)&prime_list);
		
		/* clear every mpz */
		while (prime_list->primes->get_count(prime_list->primes) > 0)
		{
			mpz_t *prime;
			prime_list->primes->remove_last(prime_list->primes, (void**)&prime);
			mpz_clear(*prime);
			allocator_free(prime);
		}
		prime_list->primes->destroy(prime_list->primes);
		allocator_free(prime_list);
	}
	this->prime_lists->destroy(this->prime_lists);

	pthread_mutex_destroy(&(this->mutex));
	pthread_cond_destroy(&(this->condvar));
	
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);

	allocator_free(this);
}

/*
 * Documented in header,
 */
prime_pool_t *prime_pool_create(int generation_limit)
{
	private_prime_pool_t *this = allocator_alloc_thing(private_prime_pool_t);
	
	/* public functions */
	this->public.get_count = (int(*)(prime_pool_t*,size_t)) get_count;
	this->public.get_prime = (void(*)(prime_pool_t*,size_t,mpz_t*)) get_prime;
	this->public.destroy = (void(*)(prime_pool_t*)) destroy;

	/* private members */
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, PRIME_POOL, NULL);
	this->generate_primes = generate_primes;
	this->compute_prime = compute_prime;
	this->generation_limit = generation_limit;
	this->prime_lists = linked_list_create();
	pthread_mutex_init(&(this->mutex), NULL);
	pthread_cond_init(&(this->condvar), NULL);
	
	
	/* thread is only created if he has anything to do */
	if (generation_limit > 0)
	{
		if (pthread_create(&(this->thread), NULL, (void*(*)(void*))this->generate_primes, this) != 0)
		{
			/* failed. we live with that problem, since getting primes is still possible */
			this->logger->log(this->logger, ERROR, "Thread creation failed, working without thread!");
		}
		/* set priority */
		else
		{
			struct sched_param param;
			int policy;
			/* get params first */
			if (pthread_getschedparam(this->thread, &policy, &param) == 0)
			{
				param.sched_priority = sched_get_priority_min(policy);
				if (pthread_setschedparam(this->thread, policy, &param) != 0)
				{
					/* failed to set priority */	
				this->logger->log(this->logger, ERROR, "Could not reduce priority of thread, running in default priority!");
				}
			}
			else
			{
				/* failed to get priority */	
				this->logger->log(this->logger, ERROR, "Could not reduce priority of thread, running in default priority!");
			}
		}
	}
	return (&this->public);
}
