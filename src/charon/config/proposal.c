/*
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2006 Martin Willi
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

#include <string.h>

#include "proposal.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/identification.h>
#include <utils/lexparser.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>


ENUM(protocol_id_names, PROTO_NONE, PROTO_ESP,
	"PROTO_NONE",
	"IKE",
	"AH",
	"ESP",
);

ENUM_BEGIN(transform_type_names, UNDEFINED_TRANSFORM_TYPE, UNDEFINED_TRANSFORM_TYPE, 
	"UNDEFINED_TRANSFORM_TYPE");
ENUM_NEXT(transform_type_names, ENCRYPTION_ALGORITHM, EXTENDED_SEQUENCE_NUMBERS, UNDEFINED_TRANSFORM_TYPE,
	"ENCRYPTION_ALGORITHM",
	"PSEUDO_RANDOM_FUNCTION",
	"INTEGRITY_ALGORITHM",
	"DIFFIE_HELLMAN_GROUP",
	"EXTENDED_SEQUENCE_NUMBERS");
ENUM_END(transform_type_names, EXTENDED_SEQUENCE_NUMBERS);

ENUM(extended_sequence_numbers_names, NO_EXT_SEQ_NUMBERS, EXT_SEQ_NUMBERS,
	"NO_EXT_SEQ_NUMBERS",
	"EXT_SEQ_NUMBERS",
);

typedef struct private_proposal_t private_proposal_t;
typedef struct algorithm_t algorithm_t;

/**
 * Private data of an proposal_t object
 */
struct private_proposal_t {

	/**
	 * Public part
	 */
	proposal_t public;
	
	/**
	 * protocol (ESP or AH)
	 */
	protocol_id_t protocol;
	
	/**
	 * priority ordered list of encryption algorithms
	 */
	linked_list_t *encryption_algos;
	
	/**
	 * priority ordered list of integrity algorithms
	 */
	linked_list_t *integrity_algos;
	
	/**
	 * priority ordered list of pseudo random functions
	 */
	linked_list_t *prf_algos;
	
	/**
	 * priority ordered list of dh groups
	 */
	linked_list_t *dh_groups;
	
	/**
	 * priority ordered list of extended sequence number flags
	 */
	linked_list_t *esns;
	
	/** 
	 * senders SPI
	 */
	u_int64_t spi;
};

/**
 * Struct used to store different kinds of algorithms. 
 */
struct algorithm_t {
	/**
	 * Value from an encryption_algorithm_t/integrity_algorithm_t/...
	 */
	u_int16_t algorithm;
	
	/**
	 * the associated key size in bits, or zero if not needed
	 */
	u_int16_t key_size;
};

/**
 * Add algorithm/keysize to a algorithm list
 */
static void add_algo(linked_list_t *list, u_int16_t algo, u_int16_t key_size)
{
	algorithm_t *algo_key;
	
	algo_key = malloc_thing(algorithm_t);
	algo_key->algorithm = algo;
	algo_key->key_size = key_size;
	list->insert_last(list, (void*)algo_key);
}

/**
 * Implements proposal_t.add_algorithm
 */
static void add_algorithm(private_proposal_t *this, transform_type_t type,
						  u_int16_t algo, u_int16_t key_size)
{
	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			add_algo(this->encryption_algos, algo, key_size);
			break;
		case INTEGRITY_ALGORITHM:
			add_algo(this->integrity_algos, algo, key_size);
			break;
		case PSEUDO_RANDOM_FUNCTION:
			add_algo(this->prf_algos, algo, key_size);
			break;
		case DIFFIE_HELLMAN_GROUP:
			add_algo(this->dh_groups, algo, 0);
			break;
		case EXTENDED_SEQUENCE_NUMBERS:
			add_algo(this->esns, algo, 0);
			break;
		default:
			break;
	}
}

/**
 * filter function for peer configs
 */
static bool alg_filter(void *null, algorithm_t **in, u_int16_t *alg,
					   void **unused, u_int16_t *key_size)
{
	algorithm_t *algo = *in;
	*alg = algo->algorithm;
	if (key_size)
	{
		*key_size = algo->key_size;
	}
	return TRUE;
}

/**
 * Implements proposal_t.create_enumerator.
 */
static enumerator_t *create_enumerator(private_proposal_t *this,
									   transform_type_t type)
{
	linked_list_t *list;

	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			list = this->encryption_algos;
			break;
		case INTEGRITY_ALGORITHM:
			list = this->integrity_algos;
			break;
		case PSEUDO_RANDOM_FUNCTION:
			list = this->prf_algos;
			break;
		case DIFFIE_HELLMAN_GROUP:
			list = this->dh_groups;
			break;
		case EXTENDED_SEQUENCE_NUMBERS:
			list = this->esns;
			break;
		default:
			return NULL;
	}
	return enumerator_create_filter(list->create_enumerator(list),
									(void*)alg_filter, NULL, NULL);
}

/**
 * Implements proposal_t.get_algorithm.
 */
static bool get_algorithm(private_proposal_t *this, transform_type_t type,
						  u_int16_t *alg, u_int16_t *key_size)
{
	enumerator_t *enumerator;
	bool found = FALSE;
	
	enumerator = create_enumerator(this, type);
	if (enumerator->enumerate(enumerator, alg, key_size))
	{
		found = TRUE;
	}
	enumerator->destroy(enumerator);
	return found;
}

/**
 * Implements proposal_t.has_dh_group
 */
static bool has_dh_group(private_proposal_t *this, diffie_hellman_group_t group)
{
	bool result = FALSE;
	
	if (this->dh_groups->get_count(this->dh_groups))
	{
		algorithm_t *current;
		enumerator_t *enumerator;
		
		enumerator = this->dh_groups->create_enumerator(this->dh_groups);
		while (enumerator->enumerate(enumerator, (void**)&current))
		{
			if (current->algorithm == group)
			{
				result = TRUE;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	else if (group == MODP_NONE)
	{
		result = TRUE;
	}
	return result;
}

/**
 * Implementation of proposal_t.strip_dh.
 */
static void strip_dh(private_proposal_t *this)
{
	algorithm_t *alg;
	
	while (this->dh_groups->remove_last(this->dh_groups, (void**)&alg) == SUCCESS)
	{
		free(alg);
	}
}

/**
 * Returns true if the given alg is an authenticated encryption algorithm
 */
static bool is_authenticated_encryption(u_int16_t alg)
{
	switch(alg)
	{
		case ENCR_AES_CCM_ICV8:
		case ENCR_AES_CCM_ICV12:
		case ENCR_AES_CCM_ICV16:
		case ENCR_AES_GCM_ICV8:
		case ENCR_AES_GCM_ICV12:
		case ENCR_AES_GCM_ICV16:
			return TRUE;
	}
	return FALSE;
}

/**
 * Find a matching alg/keysize in two linked lists
 */
static bool select_algo(linked_list_t *first, linked_list_t *second, bool *add,
						u_int16_t *alg, size_t *key_size)
{
	enumerator_t *e1, *e2;
	algorithm_t *alg1, *alg2;
	
	/* if in both are zero algorithms specified, we HAVE a match */
	if (first->get_count(first) == 0 && second->get_count(second) == 0)
	{
		*add = FALSE;
		return TRUE;
	}
	
	e1 = first->create_enumerator(first);
	e2 = second->create_enumerator(second);
	/* compare algs, order of algs in "first" is preferred */
	while (e1->enumerate(e1, &alg1))
	{
		e2->destroy(e2);
		e2 = second->create_enumerator(second);
		while (e2->enumerate(e2, &alg2))
		{
			if (alg1->algorithm == alg2->algorithm &&
				alg1->key_size == alg2->key_size)
			{
				/* ok, we have an algorithm */
				*alg = alg1->algorithm;
				*key_size = alg1->key_size;
				*add = TRUE;
				e1->destroy(e1);
				e2->destroy(e2);
				return TRUE;
			}
		}
	}
	/* no match in all comparisons */
	e1->destroy(e1);
	e2->destroy(e2);
	return FALSE;
}

/**
 * Implements proposal_t.select.
 */
static proposal_t *select_proposal(private_proposal_t *this, private_proposal_t *other)
{
	proposal_t *selected;
	u_int16_t algo;
	size_t key_size;
	bool add;
	
	DBG2(DBG_CFG, "selecting proposal:");
	
	/* check protocol */
	if (this->protocol != other->protocol)
	{
		DBG2(DBG_CFG, "  protocol mismatch, skipping");
		return NULL;
	}
	
	selected = proposal_create(this->protocol);
	
	/* select encryption algorithm */
	if (select_algo(this->encryption_algos, other->encryption_algos, &add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, ENCRYPTION_ALGORITHM, algo, key_size);
		}
	}
	else
	{
		enumerator_t *e;
		algorithm_t *alg;

		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable ENCRYPTION_ALGORITHM found");
		DBG2(DBG_CFG, "  list of received ENCRYPTION_ALGORITHM proposals:");
		e = other->encryption_algos->create_enumerator(other->encryption_algos);
		while (e->enumerate(e, &alg))
		{
			DBG2(DBG_CFG, "  %N-%d", encryption_algorithm_names,
									 alg->algorithm, alg->key_size);
		}
		e->destroy(e);
		return NULL;
	}
	/* select integrity algorithm */
	if (!is_authenticated_encryption(algo))
	{
		if (select_algo(this->integrity_algos, other->integrity_algos, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, INTEGRITY_ALGORITHM, algo, key_size);
			}
		}
		else
		{
			enumerator_t *e;
			algorithm_t *alg;

			selected->destroy(selected);
			DBG2(DBG_CFG, "  no acceptable INTEGRITY_ALGORITHM found");
			DBG2(DBG_CFG, "  list of received INTEGRITY_ALGORITHM proposals:");
			e = other->integrity_algos->create_enumerator(other->integrity_algos);
			while (e->enumerate(e, &alg))
			{
				DBG2(DBG_CFG, "  %N", integrity_algorithm_names, alg->algorithm);
			}
			e->destroy(e);
			return NULL;
		}
	}
	/* select prf algorithm */
	if (select_algo(this->prf_algos, other->prf_algos, &add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, PSEUDO_RANDOM_FUNCTION, algo, key_size);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable PSEUDO_RANDOM_FUNCTION found, skipping");
		return NULL;
	}
	/* select a DH-group */
	if (select_algo(this->dh_groups, other->dh_groups, &add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, DIFFIE_HELLMAN_GROUP, algo, 0);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable DIFFIE_HELLMAN_GROUP found, skipping");
		return NULL;
	}
	/* select if we use ESNs */
	if (select_algo(this->esns, other->esns, &add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, EXTENDED_SEQUENCE_NUMBERS, algo, 0);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable EXTENDED_SEQUENCE_NUMBERS found, skipping");
		return NULL;
	}
	DBG2(DBG_CFG, "  proposal matches");
	
	/* apply SPI from "other" */
	selected->set_spi(selected, other->spi);
	
	/* everything matched, return new proposal */
	return selected;
}

/**
 * Implements proposal_t.get_protocols.
 */
static protocol_id_t get_protocol(private_proposal_t *this)
{
	return this->protocol;
}

/**
 * Implements proposal_t.set_spi.
 */
static void set_spi(private_proposal_t *this, u_int64_t spi)
{
	this->spi = spi;
}

/**
 * Implements proposal_t.get_spi.
 */
static u_int64_t get_spi(private_proposal_t *this)
{
	return this->spi;
}

/**
 * Clone a algorithm list
 */
static void clone_algo_list(linked_list_t *list, linked_list_t *clone_list)
{
	algorithm_t *algo, *clone_algo;
	enumerator_t *enumerator;
	
	enumerator = list->create_enumerator(list);
	while (enumerator->enumerate(enumerator, &algo))
	{
		clone_algo = malloc_thing(algorithm_t);
		memcpy(clone_algo, algo, sizeof(algorithm_t));
		clone_list->insert_last(clone_list, (void*)clone_algo);
	}
	enumerator->destroy(enumerator);
}

/**
 * check if an algorithm list equals
 */
static bool algo_list_equals(linked_list_t *l1, linked_list_t *l2)
{
	enumerator_t *e1, *e2;
	algorithm_t *alg1, *alg2;
	bool equals = TRUE;
	
	if (l1->get_count(l1) != l2->get_count(l2))
	{
		return FALSE;
	}
	
	e1 = l1->create_enumerator(l1);
	e2 = l2->create_enumerator(l2);
	while (e1->enumerate(e1, &alg1) && e2->enumerate(e2, &alg2))
	{
		if (alg1->algorithm != alg2->algorithm ||
			alg1->key_size != alg2->key_size)
		{
			equals = FALSE;
			break;
		}
	}
	e1->destroy(e1);
	e2->destroy(e2);
	return equals;
}

/**
 * Implementation of proposal_t.equals.
 */
static bool equals(private_proposal_t *this, private_proposal_t *other)
{
	if (this == other)
	{
		return TRUE;
	}
	if (this->public.equals != other->public.equals)
	{
		return FALSE;
	}
	return (
		algo_list_equals(this->encryption_algos, other->encryption_algos) &&
		algo_list_equals(this->integrity_algos, other->integrity_algos) &&
		algo_list_equals(this->prf_algos, other->prf_algos) &&
		algo_list_equals(this->dh_groups, other->dh_groups) &&
		algo_list_equals(this->esns, other->esns));
}

/**
 * Implements proposal_t.clone
 */
static proposal_t *clone_(private_proposal_t *this)
{
	private_proposal_t *clone = (private_proposal_t*)proposal_create(this->protocol);
	
	clone_algo_list(this->encryption_algos, clone->encryption_algos);
	clone_algo_list(this->integrity_algos, clone->integrity_algos);
	clone_algo_list(this->prf_algos, clone->prf_algos);
	clone_algo_list(this->dh_groups, clone->dh_groups);
	clone_algo_list(this->esns, clone->esns);
	
	clone->spi = this->spi;
	
	return &clone->public;
}

/**
 * Checks the proposal read from a string.
 */
static void check_proposal(private_proposal_t *this)
{
	enumerator_t *e;
	algorithm_t *alg;
	bool all_aead = TRUE;
	
	e = this->encryption_algos->create_enumerator(this->encryption_algos);
	while (e->enumerate(e, &alg))
	{
		if (!is_authenticated_encryption(alg->algorithm))
		{
			all_aead = FALSE;
			break;
		}
	}
	e->destroy(e);
	
	if (all_aead)
	{
		/* if all encryption algorithms in the proposal are authenticated encryption
		 * algorithms we MUST NOT propose any integrity algorithms */
		while (this->integrity_algos->remove_last(this->integrity_algos, (void**)&alg) == SUCCESS)
		{
			free(alg);
		}
	}
}

/**
 * add a algorithm identified by a string to the proposal.
 * TODO: we could use gperf here.
 */
static status_t add_string_algo(private_proposal_t *this, chunk_t alg)
{
	if (strncmp(alg.ptr, "null", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_NULL, 0);
	}
	else if (strncmp(alg.ptr, "aes128", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 128);
	}
	else if (strncmp(alg.ptr, "aes192", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 192);
	}
	else if (strncmp(alg.ptr, "aes256", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 256);
	}
	else if (strstr(alg.ptr, "ccm"))
	{
		u_int16_t key_size, icv_size;

		if (sscanf(alg.ptr, "aes%huccm%hu", &key_size, &icv_size) == 2)
		{
			if (key_size == 128 || key_size == 192 || key_size == 256)
			{
				switch (icv_size)
				{
					case   8: /* octets */
					case  64: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8, key_size);
						break;
					case  12: /* octets */
					case  96: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12, key_size);
						break;
					case  16: /* octets */
					case 128: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16, key_size);
						break;
					default:
						/* invalid ICV size */
						break;
				}
			}
		}
	}
	else if (strstr(alg.ptr, "gcm"))
	{
		u_int16_t key_size, icv_size;

		if (sscanf(alg.ptr, "aes%hugcm%hu", &key_size, &icv_size) == 2)
		{
			if (key_size == 128 || key_size == 192 || key_size == 256)
			{
				switch (icv_size)
				{
					case   8: /* octets */
					case  64: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8, key_size);
						break;
					case  12: /* octets */
					case  96: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12, key_size);
						break;
					case  16: /* octets */
					case 128: /* bits */
						add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16, key_size);
						break;
					default:
						/* invalid ICV size */
						break;
				}
			}
		}
	}
	else if (strncmp(alg.ptr, "3des", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_3DES, 0);
	}
	/* blowfish only uses some predefined key sizes yet */
	else if (strncmp(alg.ptr, "blowfish128", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_BLOWFISH, 128);
	}
	else if (strncmp(alg.ptr, "blowfish192", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_BLOWFISH, 192);
	}
	else if (strncmp(alg.ptr, "blowfish256", alg.len) == 0)
	{
		add_algorithm(this, ENCRYPTION_ALGORITHM, ENCR_BLOWFISH, 256);
	}
	else if (strncmp(alg.ptr, "sha", alg.len) == 0 ||
			 strncmp(alg.ptr, "sha1", alg.len) == 0)
	{
		/* sha means we use SHA for both, PRF and AUTH */
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1, 0);
		}
	}  
	else if (strncmp(alg.ptr, "sha256", alg.len) == 0 ||
			 strncmp(alg.ptr, "sha2_256", alg.len) == 0)
	{
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA2_256_128, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_256, 0);
		}
	}
	else if (strncmp(alg.ptr, "sha384", alg.len) == 0 ||
			 strncmp(alg.ptr, "sha2_384", alg.len) == 0)
	{
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA2_384_192, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_384, 0);
		}
	}
	else if (strncmp(alg.ptr, "sha512", alg.len) == 0 ||
			 strncmp(alg.ptr, "sha2_512", alg.len) == 0)
	{
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA2_512_256, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_512, 0);
		}
	}
	else if (strncmp(alg.ptr, "md5", alg.len) == 0)
	{
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 0);
		}
	}
	else if (strncmp(alg.ptr, "aesxcbc", alg.len) == 0)
	{
		add_algorithm(this, INTEGRITY_ALGORITHM, AUTH_AES_XCBC_96, 0);
		if (this->protocol == PROTO_IKE)
		{
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_AES128_XCBC, 0);
		}
	}
	else if (strncmp(alg.ptr, "modp768", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_768_BIT, 0);
	}
	else if (strncmp(alg.ptr, "modp1024", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	}
	else if (strncmp(alg.ptr, "modp1536", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_1536_BIT, 0);
	}
	else if (strncmp(alg.ptr, "modp2048", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
	}
	else if (strncmp(alg.ptr, "modp4096", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_4096_BIT, 0);
	}
	else if (strncmp(alg.ptr, "modp8192", alg.len) == 0)
	{
		add_algorithm(this, DIFFIE_HELLMAN_GROUP, MODP_8192_BIT, 0);
	}
	else
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implements proposal_t.destroy.
 */
static void destroy(private_proposal_t *this)
{
	this->encryption_algos->destroy_function(this->encryption_algos, free);
	this->integrity_algos->destroy_function(this->integrity_algos, free);
	this->prf_algos->destroy_function(this->prf_algos, free);
	this->dh_groups->destroy_function(this->dh_groups, free);
	this->esns->destroy_function(this->esns, free);
	free(this);
}

/*
 * Describtion in header-file
 */
proposal_t *proposal_create(protocol_id_t protocol)
{
	private_proposal_t *this = malloc_thing(private_proposal_t);
	
	this->public.add_algorithm = (void (*)(proposal_t*,transform_type_t,u_int16_t,u_int16_t))add_algorithm;
	this->public.create_enumerator = (enumerator_t* (*)(proposal_t*,transform_type_t))create_enumerator;
	this->public.get_algorithm = (bool (*)(proposal_t*,transform_type_t,u_int16_t*,u_int16_t*))get_algorithm;
	this->public.has_dh_group = (bool (*)(proposal_t*,diffie_hellman_group_t))has_dh_group;
	this->public.strip_dh = (void(*)(proposal_t*))strip_dh;
	this->public.select = (proposal_t* (*)(proposal_t*,proposal_t*))select_proposal;
	this->public.get_protocol = (protocol_id_t(*)(proposal_t*))get_protocol;
	this->public.set_spi = (void(*)(proposal_t*,u_int64_t))set_spi;
	this->public.get_spi = (u_int64_t(*)(proposal_t*))get_spi;
	this->public.equals = (bool(*)(proposal_t*, proposal_t *other))equals;
	this->public.clone = (proposal_t*(*)(proposal_t*))clone_;
	this->public.destroy = (void(*)(proposal_t*))destroy;
	
	this->spi = 0;
	this->protocol = protocol;
	
	this->encryption_algos = linked_list_create();
	this->integrity_algos = linked_list_create();
	this->prf_algos = linked_list_create();
	this->dh_groups = linked_list_create();
	this->esns = linked_list_create();
	
	return &this->public;
}

/*
 * Describtion in header-file
 */
proposal_t *proposal_create_default(protocol_id_t protocol)
{
	private_proposal_t *this = (private_proposal_t*)proposal_create(protocol);
	
	switch (protocol)
	{
		case PROTO_IKE:
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         128);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         192);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         256);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_3DES,              0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_AES_XCBC_96,       0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA2_256_128,	0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA1_96,      0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_MD5_96,       0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA2_384_192,	0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA2_512_256,	0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_AES128_XCBC,        0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_256,      0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1,          0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5,           0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_384,      0);
			add_algorithm(this, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_512,      0);
			add_algorithm(this, DIFFIE_HELLMAN_GROUP,   MODP_2048_BIT, 		    0);
			add_algorithm(this, DIFFIE_HELLMAN_GROUP,   MODP_1536_BIT,          0);
			add_algorithm(this, DIFFIE_HELLMAN_GROUP,   MODP_1024_BIT,          0);
			add_algorithm(this, DIFFIE_HELLMAN_GROUP,   MODP_4096_BIT,          0);
			add_algorithm(this, DIFFIE_HELLMAN_GROUP,   MODP_8192_BIT,          0);
			break;
		case PROTO_ESP:
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         128);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         192);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_AES_CBC,         256);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_3DES,              0);
			add_algorithm(this, ENCRYPTION_ALGORITHM,   ENCR_BLOWFISH,        256);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA1_96,      0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_AES_XCBC_96,       0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_MD5_96,       0);
			add_algorithm(this, EXTENDED_SEQUENCE_NUMBERS, NO_EXT_SEQ_NUMBERS,  0);
			break;
		case PROTO_AH:
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_SHA1_96,      0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_AES_XCBC_96,       0);
			add_algorithm(this, INTEGRITY_ALGORITHM,    AUTH_HMAC_MD5_96,       0);
			add_algorithm(this, EXTENDED_SEQUENCE_NUMBERS, NO_EXT_SEQ_NUMBERS,  0);
			break;
		default:
			break;
	}
	
	return &this->public;
}

/*
 * Describtion in header-file
 */
proposal_t *proposal_create_from_string(protocol_id_t protocol, const char *algs)
{
	private_proposal_t *this = (private_proposal_t*)proposal_create(protocol);
	chunk_t string = {(void*)algs, strlen(algs)};
	chunk_t alg;
	status_t status = SUCCESS;
	
	eat_whitespace(&string);
	if (string.len < 1)
	{
		destroy(this);
		return NULL;
	}
	
	/* get all tokens, separated by '-' */
	while (extract_token(&alg, '-', &string))
	{
		status |= add_string_algo(this, alg);
	}
	if (string.len)
	{
		status |= add_string_algo(this, string);
	}
	if (status != SUCCESS)
	{
		destroy(this);
		return NULL;
	}
	
	check_proposal(this);
	
	if (protocol == PROTO_AH || protocol == PROTO_ESP)
	{
		add_algorithm(this, EXTENDED_SEQUENCE_NUMBERS, NO_EXT_SEQ_NUMBERS, 0);
	}
	return &this->public;
}
