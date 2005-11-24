/**
 * @file gmp_helper.c
 * 
 * @brief Class with helper functions for gmp operations
 * 
 */

/*
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
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
 
#include <stdio.h>
 
#include "gmp_helper.h"

#include <utils/allocator.h>
#include <utils/randomizer.h>

/**
 * Number of times the probabilistic primality test is applied
 */
#define PRIMECHECK_ROUNDS 30

typedef struct private_gmp_helper_t private_gmp_helper_t;

/**
 * Private data of an gmp_helper_t object.
 */
struct private_gmp_helper_t {
	/**
	 * public gmp_helper_t interface
	 */
	gmp_helper_t public;

};


/**
 * Implements private_gmp_helper_t's chunk_to_mpz function.
 * See #private_gmp_helper_t.chunk_to_mpz for description.
 */
static void chunk_to_mpz(private_gmp_helper_t *this, mpz_t *mpz_value, chunk_t data)
{
    size_t i;

    mpz_init_set_ui(*(mpz_value), 0);

    for (i = 0; i < data.len; i++)
    {
		mpz_mul_ui(*(mpz_value),*(mpz_value), 1 << 8);
		mpz_add_ui(*(mpz_value),*(mpz_value), data.ptr[i]);
    }
}

/**
 * Implements private_gmp_helper_t's mpz_to_chunk function.
 * See #private_gmp_helper_t.mpz_to_chunk for description.
 */
static status_t mpz_to_chunk (private_gmp_helper_t *this,mpz_t *mpz_value, chunk_t *data,size_t bytes)
{
    mpz_t temp1, temp2;
    status_t status = SUCCESS;
    int i;
    chunk_t tmp_chunk;

    tmp_chunk.len = bytes;
    tmp_chunk.ptr = allocator_alloc(tmp_chunk.len);
    
    if (tmp_chunk.ptr == NULL)
    {
    		allocator_free_chunk(tmp_chunk);
	    	return OUT_OF_RES;
    }

    /* free memory */
    memset(tmp_chunk.ptr,0,tmp_chunk.len);

    mpz_init(temp1);
    mpz_init(temp2);

    mpz_set(temp1, *mpz_value);

    for (i = tmp_chunk.len-1; i >= 0; i--)
    {
		tmp_chunk.ptr[i] = mpz_mdivmod_ui(temp2, NULL, temp1, 1 << 8);
		mpz_set(temp1, temp2);

    }

    if (mpz_sgn(temp1) != 0)
    {
	    fprintf (stderr,"value %d\n",mpz_sgn(temp1));
		status = FAILED;
    }
    mpz_clear(temp1);
    mpz_clear(temp2);
    *data = tmp_chunk;
	if (status != SUCCESS)
	{
    		allocator_free_chunk(tmp_chunk);
	}
    return status;
}

/**
 * Implements gmp_helper_t's init_prime function.
 * See #gmp_helper_t.init_prime for description.
 */
static status_t init_prime (private_gmp_helper_t *this, mpz_t *prime, int bytes)
{
    randomizer_t *randomizer;
    chunk_t random_bytes;
    status_t status;  
    randomizer = randomizer_create();
    
    if (randomizer == NULL)
    {
    		return OUT_OF_RES;
    } 
    
    /* TODO change to true random device ? */
 //  	status = randomizer->allocate_random_bytes(randomizer,bytes, &random_bytes);
   	status = randomizer->allocate_pseudo_random_bytes(randomizer,bytes, &random_bytes);
   	
   	/* make sure most significant bit is set */
   	random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
   	
   	
   	/* not needed anymore */
   	randomizer->destroy(randomizer);
   	if (status != SUCCESS)
   	{
   		return status;
   	}
  	   	
   	/* convert chunk to mpz value */
   	this->public.chunk_to_mpz(&(this->public),prime, random_bytes);

   	/* chunk is not used anymore */
   	allocator_free(random_bytes.ptr);
   	random_bytes.ptr = NULL;   

	/* composites are possible but should never occur */
	mpz_nextprime (*(prime),*(prime));

	return SUCCESS;
}


static status_t init_prime_fast (private_gmp_helper_t *this, mpz_t *prime, int bytes){
	randomizer_t *randomizer;
    chunk_t random_bytes;
    status_t status;  
    unsigned long tries;
    size_t length;

    
    randomizer = randomizer_create();
    
    if (randomizer == NULL)
    {
    		return OUT_OF_RES;
    } 
    
    /* TODO change to true random device ? */
 //  	status = randomizer->allocate_random_bytes(randomizer,bytes, &random_bytes);
   	status = randomizer->allocate_pseudo_random_bytes(randomizer,bytes, &random_bytes);
   	
   	/* make sure most significant bit is set */
   	random_bytes.ptr[0] = random_bytes.ptr[0] | 0x80;
   	/* not needed anymore */
   	randomizer->destroy(randomizer);
   	if (status != SUCCESS)
   	{
   		return status;
   	}

   	/* convert chunk to mpz value */
   	this->public.chunk_to_mpz(&(this->public),prime, random_bytes);

   	/* chunk is not used anymore */
   	allocator_free(random_bytes.ptr);
   	random_bytes.ptr = NULL;   
	
	/* make value odd */
	if (mpz_fdiv_ui(*prime, 2) != 1)
	{
		/* make value odd */
		mpz_add_ui(*prime,*prime,1);
	}
	
    tries = 1;
	
	/* starting find a prime */	
	while (!mpz_probab_prime_p(*prime, PRIMECHECK_ROUNDS))
    {
		/* not a prime, increase by 2 */
		mpz_add_ui(*prime, *prime, 2);
		tries++;
    }

    length = mpz_sizeinbase(*prime, 2);


    /* check bit length of primee */
	if ((length < (bytes * 8)) || (length > ((bytes * 8) + 1)))
	{
		return FAILED;
	}
	

    if (length == ((bytes * 8) + 1))
    {
    		/* carry out occured! retry */
		mpz_clear(*prime);

		/* recursive call */
    		return this->public.init_prime_fast(&(this->public),prime, bytes);
    }

    return SUCCESS;
}


/**
 * Implements gmp_helper_t's destroy function.
 * See #gmp_helper_t.destroy for description.
 */
static status_t destroy(private_gmp_helper_t *this)
{
	allocator_free(this);
	return SUCCESS;
}

/*
 * Described in header
 */
gmp_helper_t *gmp_helper_create()
{
	private_gmp_helper_t *this = allocator_alloc_thing(private_gmp_helper_t);
	if ((this == NULL))
	{
		return NULL;
	}
	
	/* public functions */
	this->public.destroy = (status_t (*)(gmp_helper_t *)) destroy;
	this->public.init_prime = (status_t (*) (gmp_helper_t *, mpz_t *, int)) init_prime;
	this->public.init_prime_fast = (status_t (*) (gmp_helper_t *, mpz_t *, int)) init_prime_fast;
	
	/* private functions */	
	this->public.chunk_to_mpz = (void (*) (gmp_helper_t *,mpz_t *, chunk_t )) chunk_to_mpz;
	this->public.mpz_to_chunk = (status_t (*) (gmp_helper_t *,mpz_t *, chunk_t *,size_t )) mpz_to_chunk;
	
	return &(this->public);
}
