/**
 * @file gmp_helper.c
 * 
 * @brief Class with helper functions for gmp operations
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
 
#include "gmp_helper.h"

#include "allocator.h"
#include "randomizer.h"

/**
 * Private data of an gmp_helper_t object.
 * 
 */
typedef struct private_gmp_helper_s private_gmp_helper_t;

struct private_gmp_helper_s {
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

    data->len = bytes;
    data->ptr = allocator_alloc(data->len);
    
    if (data->ptr == NULL)
    {
	    	return OUT_OF_RES;
    }

    /* free memory */
    memset(data->ptr,0,data->len);

    mpz_init(temp1);
    mpz_init(temp2);

    mpz_set(temp1, *mpz_value);

    for (i = data->len-1; i >= 0; i--)
    {
		data->ptr[i] = mpz_mdivmod_ui(temp2, NULL, temp1, 1 << 8);
		mpz_set(temp1, temp2);

    }

    if (mpz_sgn(temp1) != 0)
    {
		status = FAILED;
    }
    mpz_clear(temp1);
    mpz_clear(temp2);
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
    
   	status = randomizer->allocate_random_bytes(randomizer,bytes, &random_bytes);
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

	mpz_nextprime (*(prime),*(prime));

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
	
	/* private functions */	
	this->public.chunk_to_mpz = (void (*) (gmp_helper_t *,mpz_t *, chunk_t )) chunk_to_mpz;
	this->public.mpz_to_chunk = (status_t (*) (gmp_helper_t *,mpz_t *, chunk_t *,size_t )) mpz_to_chunk;
	
	return &(this->public);
}
