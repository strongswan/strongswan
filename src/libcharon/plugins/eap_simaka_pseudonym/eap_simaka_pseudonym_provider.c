/*
 * Copyright (C) 2009 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#include "eap_simaka_pseudonym_provider.h"

#include <utils/debug.h>
#include <collections/hashtable.h>
#include <threading/rwlock.h>

typedef struct private_eap_simaka_pseudonym_provider_t private_eap_simaka_pseudonym_provider_t;

/**
 * Private data of an eap_simaka_pseudonym_provider_t object.
 */
struct private_eap_simaka_pseudonym_provider_t {

	/**
	 * Public eap_simaka_pseudonym_provider_t interface.
	 */
	eap_simaka_pseudonym_provider_t public;

	/**
	 * Permanent -> pseudonym mappings
	 */
	hashtable_t *pseudonym;

	/**
	 * Reverse pseudonym -> permanent mappings
	 */
	hashtable_t *permanent;

	/**
	 * RNG for pseudonyms/reauth identities
	 */
	rng_t *rng;

	/**
	 * Lock for pseudonym mappings
	 */
	rwlock_t *lock;
};

/**
 * hashtable hash function
 */
static u_int hash(identification_t *key)
{
	return chunk_hash(key->get_encoding(key));
}

/**
 * hashtable equals function
 */
static bool equals(identification_t *key1, identification_t *key2)
{
	return key1->equals(key1, key2);
}

METHOD(simaka_provider_t, is_pseudonym, identification_t*,
	private_eap_simaka_pseudonym_provider_t *this, identification_t *id)
{
	identification_t *permanent;

	this->lock->read_lock(this->lock);
	permanent = this->permanent->get(this->permanent, id);
	if (permanent)
	{
		permanent = permanent->clone(permanent);
	}
	this->lock->unlock(this->lock);
	return permanent;
}

/**
 * Generate a random identity
 */
static identification_t *gen_identity(
								private_eap_simaka_pseudonym_provider_t *this)
{
	char buf[8], hex[sizeof(buf) * 2 + 1];

	if (!this->rng->get_bytes(this->rng, sizeof(buf), buf))
	{
		return NULL;
	}
	chunk_to_hex(chunk_create(buf, sizeof(buf)), hex, FALSE);

	return identification_create_from_string(hex);
}

METHOD(simaka_provider_t, gen_pseudonym, identification_t*,
	private_eap_simaka_pseudonym_provider_t *this, identification_t *id)
{
	identification_t *pseudonym, *permanent;

	this->lock->write_lock(this->lock);

	/* remove old entry */
	pseudonym = this->pseudonym->remove(this->pseudonym, id);
	if (pseudonym)
	{
		permanent = this->permanent->remove(this->permanent, pseudonym);
		if (permanent)
		{
			permanent->destroy(permanent);
		}
		pseudonym->destroy(pseudonym);
	}

	pseudonym = gen_identity(this);
	if (!pseudonym)
	{
		this->lock->unlock(this->lock);
		DBG1(DBG_CFG, "failed to generate pseudonym");
		return NULL;
	}

	/* create new entries */
	id = id->clone(id);
	this->pseudonym->put(this->pseudonym, id, pseudonym);
	this->permanent->put(this->permanent, pseudonym, id);
	pseudonym = pseudonym->clone(pseudonym);

	this->lock->unlock(this->lock);
	return pseudonym;
}

METHOD(eap_simaka_pseudonym_provider_t, destroy, void,
	private_eap_simaka_pseudonym_provider_t *this)
{
	enumerator_t *enumerator;
	identification_t *id;
	void *key;

	enumerator = this->pseudonym->create_enumerator(this->pseudonym);
	while (enumerator->enumerate(enumerator, &key, &id))
	{
		id->destroy(id);
	}
	enumerator->destroy(enumerator);

	enumerator = this->permanent->create_enumerator(this->permanent);
	while (enumerator->enumerate(enumerator, &key, &id))
	{
		id->destroy(id);
	}
	enumerator->destroy(enumerator);

	this->pseudonym->destroy(this->pseudonym);
	this->permanent->destroy(this->permanent);
	this->lock->destroy(this->lock);
	DESTROY_IF(this->rng);
	free(this);
}

/**
 * See header
 */
eap_simaka_pseudonym_provider_t *eap_simaka_pseudonym_provider_create()
{
	private_eap_simaka_pseudonym_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.get_triplet = (void*)return_false,
				.get_quintuplet = (void*)return_false,
				.resync = (void*)return_false,
				.is_pseudonym = _is_pseudonym,
				.gen_pseudonym = _gen_pseudonym,
				.is_reauth = (void*)return_null,
				.gen_reauth = (void*)return_null,
			},
			.destroy = _destroy,
		},
		.pseudonym = hashtable_create((void*)hash, (void*)equals, 0),
		.permanent = hashtable_create((void*)hash, (void*)equals, 0),
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
	);
	if (!this->rng)
	{
		destroy(this);
		return NULL;
	}
	return &this->public;
}

