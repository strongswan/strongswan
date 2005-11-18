/**
 * @file diffie_hellman.c
 * 
 * @brief Class to represent a diffie hellman exchange.
 * 
 */

/*
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <gmp.h> 

#include "diffie_hellman.h"

#include "../payloads/transform_substructure.h"
#include "../utils/allocator.h"
#include "../utils/randomizer.h"
#include "../utils/gmp_helper.h"


/**
 * Modulus of Group 1
 */
static u_int8_t group1_modulus[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
	0xC4,0xC6,0x62,0x8B,0x80	,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
	0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
	0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
	0xF4,0x4C,0x42,0xE9,0xA6,0x3A,0x36,0x20,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};


/** 
 * Entry of the modulus list
 */
typedef struct modulus_info_entry_s modulus_info_entry_t;

struct modulus_info_entry_s{
	/**
	 * Group number as it is defined in transform_substructure.h
	 */
	diffie_hellman_group_t group;
	
	/**
	 * Pointer to first byte of modulus in (network order)
	 */
	u_int8_t *modulus;
	
	/* 
	 * Length of modulus in bytes
	 */	
	size_t modulus_length;
	
	/* 
	 * Generator value
	 */	
	u_int16_t generator;
};


static modulus_info_entry_t modulus_info_entries[] = {
	{MODP_768_BIT,group1_modulus,sizeof(group1_modulus),2},
};

/**
 * Private data of an diffie_hellman_t object.
 * 
 */
typedef struct private_diffie_hellman_s private_diffie_hellman_t;

struct private_diffie_hellman_s {
	/**
	 * public diffie_hellman_t interface
	 */
	diffie_hellman_t public;
	
	/**
	 * Diffie Hellman group number
	 */
	u_int16_t dh_group_number;

	/**
	 * Modulus
	 */
	mpz_t modulus;
	
	/**
	 * Modulus length
	 */
	size_t modulus_length;
	
	/* 
	 * Generator value
	 */	
	u_int16_t generator;

	/**
	 * My prime 
	 */
	mpz_t my_prime;
	
	/**
	 * My public value
	 */
	mpz_t my_public_value;

	/**
	 * Other public value
	 */	
	mpz_t other_public_value;
	
	/**
	 * Shared secret
	 */	
	mpz_t shared_secret;

	/**
	 * True if public modulus is computed and stored in my_public_value
	 */
	bool my_public_value_is_computed;

	/**
	 * True if shared secret is computed and stored in my_public_value
	 */
	bool shared_secret_is_computed;

	/**
	 * helper class for gmp functions
	 */	
	gmp_helper_t *gmp_helper;
	
	/**
	 * Sets the modulus for a specific diffie hellman group
	 * 
	 * @param this			calling object
	 * @return
	 * 						SUCCESS if modulus could be found
	 * 						NOT_FOUND if modulus not supported
	 */
	status_t (*set_modulus) (private_diffie_hellman_t *this);
	
	/**
	 * Makes sure my public value is computed
	 * 
	 * @param this			calling object
	 */
	void (*compute_public_value) (private_diffie_hellman_t *this);

	/**
	 * Computes shared secret (other public value must be available)
	 * 
	 * @param this			calling object
	 */
	void (*compute_shared_secret) (private_diffie_hellman_t *this);
};

/* Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 */
//static void
//compute_dh_shared(struct state *st, const chunk_t g
//, const struct oakley_group_desc *group)
//{
//    MP_INT mp_g, mp_shared;
//    struct timeval tv0, tv1;
//    unsigned long tv_diff;
//
//    gettimeofday(&tv0, NULL);
//    passert(st->st_sec_in_use);
//    n_to_mpz(&mp_g, g.ptr, g.len);
//    mpz_init(&mp_shared);
//    mpz_powm(&mp_shared, &mp_g, &st->st_sec, group->modulus);
//    mpz_clear(&mp_g);
//    freeanychunk(st->st_shared);	/* happens in odd error cases */
//    st->st_shared = mpz_to_n(&mp_shared, group->bytes);
//    mpz_clear(&mp_shared);
//    gettimeofday(&tv1, NULL);
//    tv_diff=(tv1.tv_sec  - tv0.tv_sec) * 1000000 + (tv1.tv_usec - tv0.tv_usec);
//    DBG(DBG_CRYPT, 
//    	DBG_log("compute_dh_shared(): time elapsed (%s): %ld usec"
//		, enum_show(&oakley_group_names, st->st_oakley.group->group)
//		, tv_diff);
//       );
//    /* if took more than 200 msec ... */
//    if (tv_diff > 200000) {
//	loglog(RC_LOG_SERIOUS, "WARNING: compute_dh_shared(): for %s took "
//			"%ld usec"
//		, enum_show(&oakley_group_names, st->st_oakley.group->group)
//		, tv_diff);
//    }
//
//    DBG_cond_dump_chunk(DBG_CRYPT, "DH shared secret:\n", st->st_shared);
//}


/**
 * Implements private_diffie_hellman_t's set_modulus function.
 * See #private_diffie_hellman_t.set_modulus for description.
 */
static status_t set_modulus(private_diffie_hellman_t *this)
{
	int i;
	status_t status = NOT_FOUND;
	
	for (i = 0; i < (sizeof(modulus_info_entries) / sizeof(modulus_info_entry_t)); i++)
	{
		if (modulus_info_entries[i].group == this->dh_group_number)
		{
			chunk_t modulus_chunk;
			modulus_chunk.ptr = modulus_info_entries[i].modulus;
			modulus_chunk.len = modulus_info_entries[i].modulus_length;
			this->gmp_helper->chunk_to_mpz(this->gmp_helper,&(this->modulus),modulus_chunk);
			this->modulus_length = modulus_chunk.len;
			this->generator = modulus_info_entries[i].generator;
			status = SUCCESS;
			break;
		}
	}
	return status;
}

/**
 * Implements diffie_hellman_t's set_other_public_value function.
 * See #diffie_hellman_t.set_other_public_value for description.
 */
static status_t set_other_public_value(private_diffie_hellman_t *this,chunk_t public_value)
{
	this->gmp_helper->chunk_to_mpz(this->gmp_helper,&(this->other_public_value),public_value);
	this->compute_shared_secret(this);		
	return SUCCESS;
}

/**
 * Implements diffie_hellman_t's get_other_public_value function.
 * See #diffie_hellman_t.get_other_public_value for description.
 */
static status_t get_other_public_value(private_diffie_hellman_t *this,chunk_t *public_value)
{
	if (!this->shared_secret_is_computed)
	{
		return FAILED;
	}
	return (this->gmp_helper->mpz_to_chunk(this->gmp_helper,&(this->other_public_value), public_value,this->modulus_length));
}

/**
 * Implements private_diffie_hellman_t's compute_shared_secret function.
 * See #private_diffie_hellman_t.compute_shared_secret for description.
 */
static void compute_shared_secret (private_diffie_hellman_t *this)
{
	/* initialize my public value */
	mpz_init(this->shared_secret);
	/* calculate my public value */
	mpz_powm(this->shared_secret,this->other_public_value,this->my_prime,this->modulus);

	this->shared_secret_is_computed = TRUE;
}


/**
 * Implements private_diffie_hellman_t's compute_public_value function.
 * See #private_diffie_hellman_t.compute_public_value for description.
 */
static void compute_public_value (private_diffie_hellman_t *this)
{
	mpz_t generator;
	/* initialize generator and set it*/
	mpz_init_set_ui (generator,this->generator);
	/* initialize my public value */
	mpz_init(this->my_public_value);
	/* calculate my public value */
	mpz_powm(this->my_public_value,generator,this->my_prime,this->modulus);
	/* generator not used anymore */
	mpz_clear(generator);
	this->my_public_value_is_computed = TRUE;
}

/**
 * Implements diffie_hellman_t's get_my_public_value function.
 * See #diffie_hellman_t.get_my_public_value for description.
 */
static status_t get_my_public_value(private_diffie_hellman_t *this,chunk_t *public_value)
{
	if (!this->my_public_value_is_computed)
	{
		this->compute_public_value(this);
	}
	return (this->gmp_helper->mpz_to_chunk(this->gmp_helper,&(this->my_public_value), public_value,this->modulus_length));
}

/**
 * Implements diffie_hellman_t's get_shared_secret function.
 * See #diffie_hellman_t.get_shared_secret for description.
 */
static status_t get_shared_secret(private_diffie_hellman_t *this,chunk_t *secret)
{
	if (!this->shared_secret_is_computed)
	{
		return FAILED;
	}
	return (this->gmp_helper->mpz_to_chunk(this->gmp_helper,&(this->shared_secret), secret,this->modulus_length));
}

/**
 * Implements diffie_hellman_t's destroy function.
 * See #diffie_hellman_t.destroy for description.
 */
static status_t destroy(private_diffie_hellman_t *this)
{
	this->gmp_helper->destroy(this->gmp_helper);
	mpz_clear(this->modulus);
	mpz_clear(this->my_prime);
	if (this->my_public_value_is_computed)
	{
		mpz_clear(this->my_public_value);
	}
	if (this->shared_secret_is_computed)
	{
		/* other public value gets initialized together with shared secret */
		mpz_clear(this->other_public_value);
		mpz_clear(this->shared_secret);
	}

	allocator_free(this);
	return SUCCESS;
}


/*
 * Described in header
 */
diffie_hellman_t *diffie_hellman_create(u_int16_t dh_group_number)
{
	private_diffie_hellman_t *this = allocator_alloc_thing(private_diffie_hellman_t);
	if ((this == NULL))
	{
		return NULL;
	}
	
	/* public functions */
	this->public.get_shared_secret = (status_t (*)(diffie_hellman_t *, chunk_t *)) get_shared_secret;
	this->public.set_other_public_value = (status_t (*)(diffie_hellman_t *, chunk_t )) set_other_public_value;
	this->public.get_other_public_value = (status_t (*)(diffie_hellman_t *, chunk_t *)) get_other_public_value;
	this->public.get_my_public_value = (status_t (*)(diffie_hellman_t *, chunk_t *)) get_my_public_value;
	this->public.destroy = (status_t (*)(diffie_hellman_t *)) destroy;
	
	/* private functions */
	this->set_modulus = set_modulus;
	this->compute_public_value = compute_public_value;
	this->compute_shared_secret = compute_shared_secret;
	
	/* private variables */
	this->dh_group_number = dh_group_number;
	
	this->gmp_helper = gmp_helper_create();
	
	if (this->gmp_helper == NULL)
	{
		allocator_free(this);
		return NULL;
	}

	/* set this->modulus */	
	if (this->set_modulus(this) != SUCCESS)
	{
		this->gmp_helper->destroy(this->gmp_helper);
		allocator_free(this);
		return NULL;
	}

	    
	if (this->gmp_helper->init_prime(this->gmp_helper,&(this->my_prime),10) != SUCCESS)
	{
		this->gmp_helper->destroy(this->gmp_helper);
		allocator_free(this);
		return NULL;
	}
	this->my_public_value_is_computed = FALSE;
	this->shared_secret_is_computed = FALSE;
	this->modulus_length = 0;
	
	return &(this->public);
}
