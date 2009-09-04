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
 */

#include "crypto_factory.h"

#include <debug.h>
#include <utils/mutex.h>
#include <utils/linked_list.h>
#include <crypto/crypto_tester.h>

typedef struct entry_t entry_t;
struct entry_t {
	/** algorithm */
	u_int algo;
	/* constructor */
	union {
		crypter_constructor_t create_crypter;
		signer_constructor_t create_signer;
		hasher_constructor_t create_hasher;
		prf_constructor_t create_prf;
		rng_constructor_t create_rng;
		dh_constructor_t create_dh;
	};
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
	 * registered crypters, as entry_t
	 */
	linked_list_t *crypters;

	/**
	 * registered signers, as entry_t
	 */
	linked_list_t *signers;

	/**
	 * registered hashers, as entry_t
	 */
	linked_list_t *hashers;

	/**
	 * registered prfs, as entry_t
	 */
	linked_list_t *prfs;

	/**
	 * registered rngs, as entry_t
	 */
	linked_list_t *rngs;

	/**
	 * registered diffie hellman, as entry_t
	 */
	linked_list_t *dhs;

	/**
	 * test manager to test crypto algorithms
	 */
	crypto_tester_t *tester;

	/**
	 * whether to test algorithms during registration
	 */
	bool test_on_add;

	/**
	 * whether to test algorithms on each crypto primitive construction
	 */
	bool test_on_create;

	/**
	 * rwlock to lock access to modules
	 */
	rwlock_t *lock;
};

/**
 * Implementation of crypto_factory_t.create_crypter.
 */
static crypter_t* create_crypter(private_crypto_factory_t *this,
								 encryption_algorithm_t algo, size_t key_size)
{
	enumerator_t *enumerator;
	entry_t *entry;
	crypter_t *crypter = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->crypters->create_enumerator(this->crypters);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			if (this->test_on_create &&
				!this->tester->test_crypter(this->tester, algo, key_size,
										    entry->create_crypter))
			{
				continue;
			}
			crypter = entry->create_crypter(algo, key_size);
			if (crypter)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return crypter;
}

/**
 * Implementation of crypto_factory_t.create_signer.
 */
static signer_t* create_signer(private_crypto_factory_t *this,
							   integrity_algorithm_t algo)
{
	enumerator_t *enumerator;
	entry_t *entry;
	signer_t *signer = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->signers->create_enumerator(this->signers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			if (this->test_on_create &&
				!this->tester->test_signer(this->tester, algo,
										   entry->create_signer))
			{
				continue;
			}
			signer = entry->create_signer(algo);
			if (signer)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	return signer;
}

/**
 * Implementation of crypto_factory_t.create_hasher.
 */
static hasher_t* create_hasher(private_crypto_factory_t *this,
							   hash_algorithm_t algo)
{
	enumerator_t *enumerator;
	entry_t *entry;
	hasher_t *hasher = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->hashers->create_enumerator(this->hashers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (algo == HASH_PREFERRED || entry->algo == algo)
		{
			if (this->test_on_create && algo != HASH_PREFERRED &&
				!this->tester->test_hasher(this->tester, algo,
										   entry->create_hasher))
			{
				continue;
			}
			hasher = entry->create_hasher(entry->algo);
			if (hasher)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return hasher;
}

/**
 * Implementation of crypto_factory_t.create_prf.
 */
static prf_t* create_prf(private_crypto_factory_t *this,
						 pseudo_random_function_t algo)
{
	enumerator_t *enumerator;
	entry_t *entry;
	prf_t *prf = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->prfs->create_enumerator(this->prfs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == algo)
		{
			if (this->test_on_create &&
				!this->tester->test_prf(this->tester, algo, entry->create_prf))
			{
				continue;
			}
			prf = entry->create_prf(algo);
			if (prf)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return prf;
}

/**
 * Implementation of crypto_factory_t.create_rng.
 */
static rng_t* create_rng(private_crypto_factory_t *this, rng_quality_t quality)
{
	enumerator_t *enumerator;
	entry_t *entry;
	u_int diff = ~0;
	rng_constructor_t constr = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->rngs->create_enumerator(this->rngs);
	while (enumerator->enumerate(enumerator, &entry))
	{	/* find the best matching quality, but at least as good as requested */
		if (entry->algo >= quality && diff > entry->algo - quality)
		{
			if (this->test_on_create &&
				!this->tester->test_rng(this->tester, quality, entry->create_rng))
			{
				continue;
			}
			diff = entry->algo - quality;
			constr = entry->create_rng;
			if (diff == 0)
			{	/* perfect match, won't get better */
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
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
	entry_t *entry;
	diffie_hellman_t *diffie_hellman = NULL;

	this->lock->read_lock(this->lock);
	enumerator = this->dhs->create_enumerator(this->dhs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->algo == group)
		{
			diffie_hellman = entry->create_dh(group);
			if (diffie_hellman)
			{
				break;
			}
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	return diffie_hellman;
}

/**
 * Implementation of crypto_factory_t.add_crypter.
 */
static void add_crypter(private_crypto_factory_t *this,
						encryption_algorithm_t algo,
						crypter_constructor_t create)
{
	if (!this->test_on_add ||
		this->tester->test_crypter(this->tester, algo, 0, create))
	{
		entry_t *entry = malloc_thing(entry_t);

		entry->algo = algo;
		entry->create_crypter = create;
		this->lock->write_lock(this->lock);
		this->crypters->insert_last(this->crypters, entry);
		this->lock->unlock(this->lock);
	}
}

/**
 * Implementation of crypto_factory_t.remove_crypter.
 */
static void remove_crypter(private_crypto_factory_t *this,
						   crypter_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->crypters->create_enumerator(this->crypters);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_crypter == create)
		{
			this->crypters->remove_at(this->crypters, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.add_signer.
 */
static void add_signer(private_crypto_factory_t *this,
					   integrity_algorithm_t algo, signer_constructor_t create)
{
	if (!this->test_on_add ||
		this->tester->test_signer(this->tester, algo, create))
	{
		entry_t *entry = malloc_thing(entry_t);

		entry->algo = algo;
		entry->create_signer = create;
		this->lock->write_lock(this->lock);
		this->signers->insert_last(this->signers, entry);
		this->lock->unlock(this->lock);
	}
}

/**
 * Implementation of crypto_factory_t.remove_signer.
 */
static void remove_signer(private_crypto_factory_t *this,
						  signer_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->signers->create_enumerator(this->signers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_signer == create)
		{
			this->signers->remove_at(this->signers, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.add_hasher.
 */
static void add_hasher(private_crypto_factory_t *this, hash_algorithm_t algo,
					   hasher_constructor_t create)
{
	if (!this->test_on_add ||
		this->tester->test_hasher(this->tester, algo, create))
	{
		entry_t *entry = malloc_thing(entry_t);

		entry->algo = algo;
		entry->create_hasher = create;
		this->lock->write_lock(this->lock);
		this->hashers->insert_last(this->hashers, entry);
		this->lock->unlock(this->lock);
	}
}

/**
 * Implementation of crypto_factory_t.remove_hasher.
 */
static void remove_hasher(private_crypto_factory_t *this,
						  hasher_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->hashers->create_enumerator(this->hashers);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_hasher == create)
		{
			this->hashers->remove_at(this->hashers, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.add_prf.
 */
static void add_prf(private_crypto_factory_t *this,
					pseudo_random_function_t algo, prf_constructor_t create)
{
	if (!this->test_on_add ||
		this->tester->test_prf(this->tester, algo, create))
	{
		entry_t *entry = malloc_thing(entry_t);

		entry->algo = algo;
		entry->create_prf = create;
		this->lock->write_lock(this->lock);
		this->prfs->insert_last(this->prfs, entry);
		this->lock->unlock(this->lock);
	}
}

/**
 * Implementation of crypto_factory_t.remove_prf.
 */
static void remove_prf(private_crypto_factory_t *this, prf_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->prfs->create_enumerator(this->prfs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_prf == create)
		{
			this->prfs->remove_at(this->prfs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.add_rng.
 */
static void add_rng(private_crypto_factory_t *this, rng_quality_t quality,
					rng_constructor_t create)
{
	if (!this->test_on_add ||
		this->tester->test_rng(this->tester, quality, create))
	{
		entry_t *entry = malloc_thing(entry_t);

		entry->algo = quality;
		entry->create_rng = create;
		this->lock->write_lock(this->lock);
		this->rngs->insert_last(this->rngs, entry);
		this->lock->unlock(this->lock);
	}
}

/**
 * Implementation of crypto_factory_t.remove_rng.
 */
static void remove_rng(private_crypto_factory_t *this, rng_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->rngs->create_enumerator(this->rngs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_rng == create)
		{
			this->rngs->remove_at(this->rngs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.add_dh.
 */
static void add_dh(private_crypto_factory_t *this, diffie_hellman_group_t group,
				   dh_constructor_t create)
{
	entry_t *entry = malloc_thing(entry_t);

	entry->algo = group;
	entry->create_dh = create;
	this->lock->write_lock(this->lock);
	this->dhs->insert_last(this->dhs, entry);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of crypto_factory_t.remove_dh.
 */
static void remove_dh(private_crypto_factory_t *this, dh_constructor_t create)
{
	entry_t *entry;
	enumerator_t *enumerator;

	this->lock->write_lock(this->lock);
	enumerator = this->dhs->create_enumerator(this->dhs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->create_dh == create)
		{
			this->dhs->remove_at(this->dhs, enumerator);
			free(entry);
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
}

/**
 * match algorithms of an entry?
 */
static bool entry_match(entry_t *a, entry_t *b)
{
	return a->algo == b->algo;
}

/**
 * check for uniqueness of an entry
 */
static bool unique_check(linked_list_t *list, entry_t **in, entry_t **out)
{
	if (list->find_first(list, (void*)entry_match, NULL, *in) == SUCCESS)
	{
		return FALSE;
	}
	*out = *in;
	list->insert_last(list, *in);
	return TRUE;
}

/**
 * create an enumerator over entry->algo in list with locking and unique check
 */
static enumerator_t *create_enumerator(private_crypto_factory_t *this,
									   linked_list_t *list, void *filter)
{
	this->lock->read_lock(this->lock);
	return enumerator_create_filter(
				enumerator_create_filter(
					list->create_enumerator(list), (void*)unique_check,
					linked_list_create(), (void*)list->destroy),
				filter,	this->lock, (void*)this->lock->unlock);
}

/**
 * Filter function to enumerate algorithm, not entry
 */
static bool crypter_filter(void *n, entry_t **entry, encryption_algorithm_t *algo)
{
	*algo = (*entry)->algo;
	return TRUE;
}

/**
 * Implementation of crypto_factory_t.create_crypter_enumerator
 */
static enumerator_t* create_crypter_enumerator(private_crypto_factory_t *this)
{
	return create_enumerator(this, this->crypters, crypter_filter);
}

/**
 * Filter function to enumerate algorithm, not entry
 */
static bool signer_filter(void *n, entry_t **entry, integrity_algorithm_t *algo)
{
	*algo = (*entry)->algo;
	return TRUE;
}

/**
 * Implementation of crypto_factory_t.create_signer_enumerator
 */
static enumerator_t* create_signer_enumerator(private_crypto_factory_t *this)
{
	return create_enumerator(this, this->signers, signer_filter);
}

/**
 * Filter function to enumerate algorithm, not entry
 */
static bool hasher_filter(void *n, entry_t **entry, hash_algorithm_t *algo)
{
	*algo = (*entry)->algo;
	return TRUE;
}

/**
 * Implementation of crypto_factory_t.create_hasher_enumerator
 */
static enumerator_t* create_hasher_enumerator(private_crypto_factory_t *this)
{
	return create_enumerator(this, this->hashers, hasher_filter);
}

/**
 * Filter function to enumerate algorithm, not entry
 */
static bool prf_filter(void *n, entry_t **entry, pseudo_random_function_t *algo)
{
	*algo = (*entry)->algo;
	return TRUE;
}

/**
 * Implementation of crypto_factory_t.create_prf_enumerator
 */
static enumerator_t* create_prf_enumerator(private_crypto_factory_t *this)
{
	return create_enumerator(this, this->prfs, prf_filter);
}

/**
 * Filter function to enumerate algorithm, not entry
 */
static bool dh_filter(void *n, entry_t **entry, diffie_hellman_group_t *group)
{
	*group = (*entry)->algo;
	return TRUE;
}

/**
 * Implementation of crypto_factory_t.create_dh_enumerator
 */
static enumerator_t* create_dh_enumerator(private_crypto_factory_t *this)
{
	return create_enumerator(this, this->dhs, dh_filter);
}

/**
 * Implementation of crypto_factory_t.add_test_vector
 */
static void add_test_vector(private_crypto_factory_t *this,
							transform_type_t type, void *vector)
{
	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			return this->tester->add_crypter_vector(this->tester, vector);
		case INTEGRITY_ALGORITHM:
			return this->tester->add_signer_vector(this->tester, vector);
		case HASH_ALGORITHM:
			return this->tester->add_hasher_vector(this->tester, vector);
		case PSEUDO_RANDOM_FUNCTION:
			return this->tester->add_prf_vector(this->tester, vector);
		case RANDOM_NUMBER_GENERATOR:
			return this->tester->add_rng_vector(this->tester, vector);
		default:
			DBG1("%N test vectors not supported, ignored",
				 transform_type_names, type);
	}
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
	this->tester->destroy(this->tester);
	this->lock->destroy(this->lock);
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
	this->public.create_crypter_enumerator = (enumerator_t*(*)(crypto_factory_t*))create_crypter_enumerator;
	this->public.create_signer_enumerator = (enumerator_t*(*)(crypto_factory_t*))create_signer_enumerator;
	this->public.create_hasher_enumerator = (enumerator_t*(*)(crypto_factory_t*))create_hasher_enumerator;
	this->public.create_prf_enumerator = (enumerator_t*(*)(crypto_factory_t*))create_prf_enumerator;
	this->public.create_dh_enumerator = (enumerator_t*(*)(crypto_factory_t*))create_dh_enumerator;
	this->public.add_test_vector = (void(*)(crypto_factory_t*, transform_type_t type, ...))add_test_vector;
	this->public.destroy = (void(*)(crypto_factory_t*))destroy;

	this->crypters = linked_list_create();
	this->signers = linked_list_create();
	this->hashers = linked_list_create();
	this->prfs = linked_list_create();
	this->rngs = linked_list_create();
	this->dhs = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
	this->tester = crypto_tester_create();
	this->test_on_add = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.on_add", FALSE);
	this->test_on_create = lib->settings->get_bool(lib->settings,
								"libstrongswan.crypto_test.on_create", FALSE);

	return &this->public;
}

