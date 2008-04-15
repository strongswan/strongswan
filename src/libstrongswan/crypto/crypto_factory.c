/*
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "crypto_factory.h"

#include <utils/linked_list.h>
#include <utils/mutex.h>

typedef struct crypter_entry_t crypter_entry_t;
struct crypter_entry_t {
	/** encryption algorithm */
	encryption_algorithm_t algo;
	/** associated constructor */
	crypter_constructor_t create;
};

typedef struct signer_entry_t signer_entry_t;
struct signer_entry_t {
	/** integrity algorithm */
	integrity_algorithm_t algo;
	/** associated constructor */
	signer_constructor_t create;
};

typedef struct hasher_entry_t hasher_entry_t;
struct hasher_entry_t {
	/** hash algorithm */
	hash_algorithm_t algo;
	/** associated constructor */
	hasher_constructor_t create;
};

typedef struct prf_entry_t prf_entry_t;
struct prf_entry_t {
	/** hash algorithm */
	pseudo_random_function_t algo;
	/** associated constructor */
	prf_constructor_t create;
};

typedef struct rng_entry_t rng_entry_t;
struct rng_entry_t {
	/** quality of randomness */
	rng_quality_t quality;
	/** associated constructor */
	rng_constructor_t create;
};

typedef struct dh_entry_t dh_entry_t;
struct dh_entry_t {
	/** hash algorithm */
	diffie_hellman_group_t group;
	/** associated constructor */
	dh_constructor_t create;
};

typedef struct private_crypto_factory_t private_crypto_factory_t;

/**
 * private data of crypto_factory
 */
struct private_crypto_factory_t {

	/**
	 * public functions
	 */
	crypto_factory_t public;
	
	/**
	 * registered crypters, as crypter_entry_t
	 */
	linked_list_t *crypters;
	
	/**
	 * registered signers, as signer_entry_t
	 */
	linked_list_t *signers;
	
	/**
	 * registered hashers, as hasher_entry_t
	 */
	linked_list_t *hashers;
	
	/**
	 * registered prfs, as prf_entry_t
	 */
	linked_list_t *prfs;
	
	/**
	 * registered rngs, as rng_entry_t
	 */
	linked_list_t *rngs;
	
	/**
	 * registered diffie hellman, as dh_entry_t
	 */
	linked_list_t *dhs;
	
	/**
	 * mutex to lock access to modules
	 */
	mutex_t *mutex;
};

/**
 * Implementation of crypto_factory_t.create_crypter.
 */
static crypter_t* create_crypter(private_crypto_factory_t *this,
								 encryption_algorithm_t algo, size_t key_size)
{
	enumerator_t *enumerator;
	crypter_entry_t *entry;
	crypter_t *crypter = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->crypters->create_enumerator(this->crypters);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			crypter = entry->create(algo, key_size);
			if (crypter)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return crypter;
}

/**
 * Implementation of crypto_factory_t.create_signer.
 */
static signer_t* create_signer(private_crypto_factory_t *this,
							   integrity_algorithm_t algo)
{
	enumerator_t *enumerator;
	signer_entry_t *entry;
	signer_t *signer = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->signers->create_enumerator(this->signers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			signer = entry->create(algo);
			if (signer)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	return signer;
}

/**
 * Implementation of crypto_factory_t.create_hasher.
 */
static hasher_t* create_hasher(private_crypto_factory_t *this,
							   hash_algorithm_t algo)
{
	enumerator_t *enumerator;
	hasher_entry_t *entry;
	hasher_t *hasher = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->hashers->create_enumerator(this->hashers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (algo == HASH_PREFERRED || entry->algo == algo)
		{
			hasher = entry->create(entry->algo);
			if (hasher)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return hasher;
}

/**
 * Implementation of crypto_factory_t.create_prf.
 */
static prf_t* create_prf(private_crypto_factory_t *this,
						 pseudo_random_function_t algo)
{
	enumerator_t *enumerator;
	prf_entry_t *entry;
	prf_t *prf = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->prfs->create_enumerator(this->prfs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			prf = entry->create(algo);
			if (prf)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return prf;
}

/**
 * Implementation of crypto_factory_t.create_rng.
 */
static rng_t* create_rng(private_crypto_factory_t *this, rng_quality_t quality)
{
	enumerator_t *enumerator;
	rng_entry_t *entry;
	u_int diff = ~0;
	rng_constructor_t constr = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->rngs->create_enumerator(this->rngs);
	while (enumerator->enumerate(enumerator, &entry))
	{	/* find the best matching quality, but at least as good as requested */
		if (entry->quality >= quality && diff > entry->quality - quality)
		{
			diff = entry->quality - quality;
			constr = entry->create;
			if (diff == 0)
			{	/* perfect match, won't get better */
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	if (constr)
	{
		return constr(quality);
	}
	return NULL;
}

/**
 * Implementation of crypto_factory_t.create_dh.
 */
static diffie_hellman_t* create_dh(private_crypto_factory_t *this,
								   diffie_hellman_group_t group)
{
	enumerator_t *enumerator;
	dh_entry_t *entry;
	diffie_hellman_t *diffie_hellman = NULL;

	this->mutex->lock(this->mutex);
	enumerator = this->dhs->create_enumerator(this->dhs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->group == group)
		{
			diffie_hellman = entry->create(group);
			if (diffie_hellman)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
	return diffie_hellman;
}

/**
 * Implementation of crypto_factory_t.add_crypter.
 */
static void add_crypter(private_crypto_factory_t *this,
						encryption_algorithm_t algo,
						crypter_constructor_t create)
{
	crypter_entry_t *entry = malloc_thing(crypter_entry_t);
	
	entry->algo = algo;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->crypters->insert_last(this->crypters, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_crypter.
 */
static void remove_crypter(private_crypto_factory_t *this,
						   crypter_constructor_t create)
{
	crypter_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->crypters->create_enumerator(this->crypters);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->crypters->remove_at(this->crypters, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.add_signer.
 */
static void add_signer(private_crypto_factory_t *this,
					   integrity_algorithm_t algo, signer_constructor_t create)
{
	signer_entry_t *entry = malloc_thing(signer_entry_t);
	
	entry->algo = algo;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->signers->insert_last(this->signers, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_signer.
 */
static void remove_signer(private_crypto_factory_t *this,
						  signer_constructor_t create)
{
	signer_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->signers->create_enumerator(this->signers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->signers->remove_at(this->signers, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.add_hasher.
 */
static void add_hasher(private_crypto_factory_t *this, hash_algorithm_t algo,
					   hasher_constructor_t create)
{
	hasher_entry_t *entry = malloc_thing(hasher_entry_t);
	
	entry->algo = algo;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->hashers->insert_last(this->hashers, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_hasher.
 */
static void remove_hasher(private_crypto_factory_t *this,
						  hasher_constructor_t create)
{
	hasher_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->hashers->create_enumerator(this->hashers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->hashers->remove_at(this->hashers, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.add_prf.
 */
static void add_prf(private_crypto_factory_t *this,
					pseudo_random_function_t algo, prf_constructor_t create)
{
	prf_entry_t *entry = malloc_thing(prf_entry_t);
	
	entry->algo = algo;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->prfs->insert_last(this->prfs, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_prf.
 */
static void remove_prf(private_crypto_factory_t *this, prf_constructor_t create)
{
	prf_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->prfs->create_enumerator(this->prfs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->prfs->remove_at(this->prfs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.add_rng.
 */
static void add_rng(private_crypto_factory_t *this, rng_quality_t quality,
					rng_constructor_t create)
{
	rng_entry_t *entry = malloc_thing(rng_entry_t);
	
	entry->quality = quality;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->rngs->insert_last(this->rngs, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_rng.
 */
static void remove_rng(private_crypto_factory_t *this, rng_constructor_t create)
{
	rng_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->rngs->create_enumerator(this->rngs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->rngs->remove_at(this->rngs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.add_dh.
 */
static void add_dh(private_crypto_factory_t *this, diffie_hellman_group_t group,
				   dh_constructor_t create)
{
	dh_entry_t *entry = malloc_thing(dh_entry_t);
	
	entry->group = group;
	entry->create = create;
	this->mutex->lock(this->mutex);
	this->dhs->insert_last(this->dhs, entry);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.remove_dh.
 */
static void remove_dh(private_crypto_factory_t *this, dh_constructor_t create)
{
	dh_entry_t *entry;
	enumerator_t *enumerator;
	
	this->mutex->lock(this->mutex);
	enumerator = this->dhs->create_enumerator(this->dhs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create == create)
		{
			this->dhs->remove_at(this->dhs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of crypto_factory_t.destroy
 */
static void destroy(private_crypto_factory_t *this)
{
	this->crypters->destroy_function(this->crypters, free);
	this->signers->destroy_function(this->signers, free);
	this->hashers->destroy_function(this->hashers, free);
	this->prfs->destroy_function(this->prfs, free);
	this->rngs->destroy_function(this->rngs, free);
	this->dhs->destroy_function(this->dhs, free);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * see header file
 */
crypto_factory_t *crypto_factory_create()
{
	private_crypto_factory_t *this = malloc_thing(private_crypto_factory_t);
	
	this->public.create_crypter = (crypter_t*(*)(crypto_factory_t*, encryption_algorithm_t, size_t))create_crypter;
	this->public.create_signer = (signer_t*(*)(crypto_factory_t*, integrity_algorithm_t))create_signer;
	this->public.create_hasher = (hasher_t*(*)(crypto_factory_t*, hash_algorithm_t))create_hasher;
	this->public.create_prf = (prf_t*(*)(crypto_factory_t*, pseudo_random_function_t))create_prf;
	this->public.create_rng = (rng_t*(*)(crypto_factory_t*, rng_quality_t quality))create_rng;
	this->public.create_dh = (diffie_hellman_t*(*)(crypto_factory_t*, diffie_hellman_group_t group))create_dh;
	this->public.add_crypter = (void(*)(crypto_factory_t*, encryption_algorithm_t algo, crypter_constructor_t create))add_crypter;
	this->public.remove_crypter = (void(*)(crypto_factory_t*, crypter_constructor_t create))remove_crypter;
	this->public.add_signer = (void(*)(crypto_factory_t*, integrity_algorithm_t algo, signer_constructor_t create))add_signer;
	this->public.remove_signer = (void(*)(crypto_factory_t*, signer_constructor_t create))remove_signer;
	this->public.add_hasher = (void(*)(crypto_factory_t*, hash_algorithm_t algo, hasher_constructor_t create))add_hasher;
	this->public.remove_hasher = (void(*)(crypto_factory_t*, hasher_constructor_t create))remove_hasher;
	this->public.add_prf = (void(*)(crypto_factory_t*, pseudo_random_function_t algo, prf_constructor_t create))add_prf;
	this->public.remove_prf = (void(*)(crypto_factory_t*, prf_constructor_t create))remove_prf;
	this->public.add_rng = (void(*)(crypto_factory_t*, rng_quality_t quality, rng_constructor_t create))add_rng;
	this->public.remove_rng = (void(*)(crypto_factory_t*, rng_constructor_t create))remove_rng;
	this->public.add_dh = (void(*)(crypto_factory_t*, diffie_hellman_group_t algo, dh_constructor_t create))add_dh;
	this->public.remove_dh = (void(*)(crypto_factory_t*, dh_constructor_t create))remove_dh;
	this->public.destroy = (void(*)(crypto_factory_t*))destroy;
	
	this->crypters = linked_list_create();
	this->signers = linked_list_create();
	this->hashers = linked_list_create();
	this->prfs = linked_list_create();
	this->rngs = linked_list_create();
	this->dhs = linked_list_create();
	this->mutex = mutex_create(MUTEX_RECURSIVE);
	
	return &this->public;
}

