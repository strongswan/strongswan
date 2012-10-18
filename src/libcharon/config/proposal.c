/*
 * Copyright (C) 2008-2012 Tobias Brunner
 * Copyright (C) 2006-2010 Martin Willi
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

#include "proposal.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <utils/identification.h>

#include <crypto/transform.h>
#include <crypto/prfs/prf.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>

ENUM(protocol_id_names, PROTO_NONE, PROTO_IPCOMP,
	"PROTO_NONE",
	"IKE",
	"AH",
	"ESP",
	"IPCOMP",
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

	/**
	 * Proposal number
	 */
	u_int number;
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

METHOD(proposal_t, add_algorithm, void,
	private_proposal_t *this, transform_type_t type,
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

METHOD(proposal_t, create_enumerator, enumerator_t*,
	private_proposal_t *this, transform_type_t type)
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

METHOD(proposal_t, get_algorithm, bool,
	private_proposal_t *this, transform_type_t type,
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

METHOD(proposal_t, has_dh_group, bool,
	private_proposal_t *this, diffie_hellman_group_t group)
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

METHOD(proposal_t, strip_dh, void,
	private_proposal_t *this, diffie_hellman_group_t keep)
{
	enumerator_t *enumerator;
	algorithm_t *alg;

	enumerator = this->dh_groups->create_enumerator(this->dh_groups);
	while (enumerator->enumerate(enumerator, (void**)&alg))
	{
		if (alg->algorithm != keep)
		{
			this->dh_groups->remove_at(this->dh_groups, enumerator);
			free(alg);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Find a matching alg/keysize in two linked lists
 */
static bool select_algo(linked_list_t *first, linked_list_t *second, bool priv,
						bool *add, u_int16_t *alg, size_t *key_size)
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
				if (!priv && alg1->algorithm >= 1024)
				{
					/* accept private use algorithms only if requested */
					DBG1(DBG_CFG, "an algorithm from private space would match, "
						 "but peer implementation is unknown, skipped");
					continue;
				}
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

METHOD(proposal_t, select_proposal, proposal_t*,
	private_proposal_t *this, proposal_t *other_pub, bool private)
{
	private_proposal_t *other = (private_proposal_t*)other_pub;
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

	selected = proposal_create(this->protocol, other->number);

	/* select encryption algorithm */
	if (select_algo(this->encryption_algos, other->encryption_algos, private,
					&add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, ENCRYPTION_ALGORITHM,
									algo, key_size);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable %N found",
			 transform_type_names, ENCRYPTION_ALGORITHM);
		return NULL;
	}
	/* select integrity algorithm */
	if (!encryption_algorithm_is_aead(algo))
	{
		if (select_algo(this->integrity_algos, other->integrity_algos, private,
						&add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, INTEGRITY_ALGORITHM,
										algo, key_size);
			}
		}
		else
		{
			selected->destroy(selected);
			DBG2(DBG_CFG, "  no acceptable %N found",
				 transform_type_names, INTEGRITY_ALGORITHM);
			return NULL;
		}
	}
	/* select prf algorithm */
	if (select_algo(this->prf_algos, other->prf_algos, private,
					&add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, PSEUDO_RANDOM_FUNCTION,
									algo, key_size);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable %N found",
			 transform_type_names, PSEUDO_RANDOM_FUNCTION);
		return NULL;
	}
	/* select a DH-group */
	if (select_algo(this->dh_groups, other->dh_groups, private,
					&add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, DIFFIE_HELLMAN_GROUP, algo, 0);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable %N found",
			 transform_type_names, DIFFIE_HELLMAN_GROUP);
		return NULL;
	}
	/* select if we use ESNs (has no private use space) */
	if (select_algo(this->esns, other->esns, TRUE, &add, &algo, &key_size))
	{
		if (add)
		{
			selected->add_algorithm(selected, EXTENDED_SEQUENCE_NUMBERS, algo, 0);
		}
	}
	else
	{
		selected->destroy(selected);
		DBG2(DBG_CFG, "  no acceptable %N found",
			 transform_type_names, EXTENDED_SEQUENCE_NUMBERS);
		return NULL;
	}
	DBG2(DBG_CFG, "  proposal matches");

	/* apply SPI from "other" */
	selected->set_spi(selected, other->spi);

	/* everything matched, return new proposal */
	return selected;
}

METHOD(proposal_t, get_protocol, protocol_id_t,
	private_proposal_t *this)
{
	return this->protocol;
}

METHOD(proposal_t, set_spi, void,
	private_proposal_t *this, u_int64_t spi)
{
	this->spi = spi;
}

METHOD(proposal_t, get_spi, u_int64_t,
	private_proposal_t *this)
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

METHOD(proposal_t, get_number, u_int,
	private_proposal_t *this)
{
	return this->number;
}

METHOD(proposal_t, equals, bool,
	private_proposal_t *this, proposal_t *other_pub)
{
	private_proposal_t *other = (private_proposal_t*)other_pub;

	if (this == other)
	{
		return TRUE;
	}
	return (
		algo_list_equals(this->encryption_algos, other->encryption_algos) &&
		algo_list_equals(this->integrity_algos, other->integrity_algos) &&
		algo_list_equals(this->prf_algos, other->prf_algos) &&
		algo_list_equals(this->dh_groups, other->dh_groups) &&
		algo_list_equals(this->esns, other->esns));
}

METHOD(proposal_t, clone_, proposal_t*,
	private_proposal_t *this)
{
	private_proposal_t *clone;

	clone = (private_proposal_t*)proposal_create(this->protocol, 0);
	clone_algo_list(this->encryption_algos, clone->encryption_algos);
	clone_algo_list(this->integrity_algos, clone->integrity_algos);
	clone_algo_list(this->prf_algos, clone->prf_algos);
	clone_algo_list(this->dh_groups, clone->dh_groups);
	clone_algo_list(this->esns, clone->esns);

	clone->spi = this->spi;
	clone->number = this->number;

	return &clone->public;
}

/**
 * Map integrity algorithms to the PRF functions using the same algorithm.
 */
static const struct {
	integrity_algorithm_t integ;
	pseudo_random_function_t prf;
} integ_prf_map[] = {
	{AUTH_HMAC_SHA1_96,					PRF_HMAC_SHA1					},
	{AUTH_HMAC_SHA2_256_128,			PRF_HMAC_SHA2_256				},
	{AUTH_HMAC_SHA2_384_192,			PRF_HMAC_SHA2_384				},
	{AUTH_HMAC_SHA2_512_256,			PRF_HMAC_SHA2_512				},
	{AUTH_HMAC_MD5_96,					PRF_HMAC_MD5					},
	{AUTH_AES_XCBC_96,					PRF_AES128_XCBC					},
	{AUTH_CAMELLIA_XCBC_96,				PRF_CAMELLIA128_XCBC			},
	{AUTH_AES_CMAC_96,					PRF_AES128_CMAC					},
};

/**
 * Checks the proposal read from a string.
 */
static void check_proposal(private_proposal_t *this)
{
	enumerator_t *e;
	algorithm_t *alg;
	bool all_aead = TRUE;
	int i;

	if (this->protocol == PROTO_IKE &&
		this->prf_algos->get_count(this->prf_algos) == 0)
	{	/* No explicit PRF found. We assume the same algorithm as used
		 * for integrity checking */
		e = this->integrity_algos->create_enumerator(this->integrity_algos);
		while (e->enumerate(e, &alg))
		{
			for (i = 0; i < countof(integ_prf_map); i++)
			{
				if (alg->algorithm == integ_prf_map[i].integ)
				{
					add_algorithm(this, PSEUDO_RANDOM_FUNCTION,
								  integ_prf_map[i].prf, 0);
					break;
				}
			}
		}
		e->destroy(e);
	}

	e = this->encryption_algos->create_enumerator(this->encryption_algos);
	while (e->enumerate(e, &alg))
	{
		if (!encryption_algorithm_is_aead(alg->algorithm))
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
		while (this->integrity_algos->remove_last(this->integrity_algos,
												  (void**)&alg) == SUCCESS)
		{
			free(alg);
		}
	}

	if (this->protocol == PROTO_AH || this->protocol == PROTO_ESP)
	{
		e = this->esns->create_enumerator(this->esns);
		if (!e->enumerate(e, &alg))
		{	/* ESN not specified, assume not supported */
			add_algorithm(this, EXTENDED_SEQUENCE_NUMBERS, NO_EXT_SEQ_NUMBERS, 0);
		}
		e->destroy(e);
	}
}

/**
 * add a algorithm identified by a string to the proposal.
 */
static bool add_string_algo(private_proposal_t *this, const char *alg)
{
	const proposal_token_t *token;

	token = lib->proposal->get_token(lib->proposal, alg);
	if (token == NULL)
	{
		DBG1(DBG_CFG, "algorithm '%s' not recognized", alg);
		return FALSE;
	}

	add_algorithm(this, token->type, token->algorithm, token->keysize);

	return TRUE;
}

/**
 * print all algorithms of a kind to buffer
 */
static int print_alg(private_proposal_t *this, printf_hook_data_t *data,
					 u_int kind, void *names, bool *first)
{
	enumerator_t *enumerator;
	size_t written = 0;
	u_int16_t alg, size;

	enumerator = create_enumerator(this, kind);
	while (enumerator->enumerate(enumerator, &alg, &size))
	{
		if (*first)
		{
			written += print_in_hook(data, "%N", names, alg);
			*first = FALSE;
		}
		else
		{
			written += print_in_hook(data, "/%N", names, alg);
		}
		if (size)
		{
			written += print_in_hook(data, "_%u", size);
		}
	}
	enumerator->destroy(enumerator);
	return written;
}

/**
 * Described in header.
 */
int proposal_printf_hook(printf_hook_data_t *data, printf_hook_spec_t *spec,
						 const void *const *args)
{
	private_proposal_t *this = *((private_proposal_t**)(args[0]));
	linked_list_t *list = *((linked_list_t**)(args[0]));
	enumerator_t *enumerator;
	size_t written = 0;
	bool first = TRUE;

	if (this == NULL)
	{
		return print_in_hook(data, "(null)");
	}

	if (spec->hash)
	{
		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &this))
		{	/* call recursivly */
			if (first)
			{
				written += print_in_hook(data, "%P", this);
				first = FALSE;
			}
			else
			{
				written += print_in_hook(data, ", %P", this);
			}
		}
		enumerator->destroy(enumerator);
		return written;
	}

	written = print_in_hook(data, "%N:", protocol_id_names, this->protocol);
	written += print_alg(this, data, ENCRYPTION_ALGORITHM,
						 encryption_algorithm_names, &first);
	written += print_alg(this, data, INTEGRITY_ALGORITHM,
						 integrity_algorithm_names, &first);
	written += print_alg(this, data, PSEUDO_RANDOM_FUNCTION,
						 pseudo_random_function_names, &first);
	written += print_alg(this, data, DIFFIE_HELLMAN_GROUP,
						 diffie_hellman_group_names, &first);
	written += print_alg(this, data, EXTENDED_SEQUENCE_NUMBERS,
						 extended_sequence_numbers_names, &first);
	return written;
}

METHOD(proposal_t, destroy, void,
	private_proposal_t *this)
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
proposal_t *proposal_create(protocol_id_t protocol, u_int number)
{
	private_proposal_t *this;

	INIT(this,
		.public = {
			.add_algorithm = _add_algorithm,
			.create_enumerator = _create_enumerator,
			.get_algorithm = _get_algorithm,
			.has_dh_group = _has_dh_group,
			.strip_dh = _strip_dh,
			.select = _select_proposal,
			.get_protocol = _get_protocol,
			.set_spi = _set_spi,
			.get_spi = _get_spi,
			.get_number = _get_number,
			.equals = _equals,
			.clone = _clone_,
			.destroy = _destroy,
		},
		.protocol = protocol,
		.number = number,
		.encryption_algos = linked_list_create(),
		.integrity_algos = linked_list_create(),
		.prf_algos = linked_list_create(),
		.dh_groups = linked_list_create(),
		.esns = linked_list_create(),
	);

	return &this->public;
}

/**
 * Add supported IKE algorithms to proposal
 */
static void proposal_add_supported_ike(private_proposal_t *this)
{
	enumerator_t *enumerator;
	encryption_algorithm_t encryption;
	integrity_algorithm_t integrity;
	pseudo_random_function_t prf;
	diffie_hellman_group_t group;
	const char *plugin_name;

	enumerator = lib->crypto->create_crypter_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &encryption, &plugin_name))
	{
		switch (encryption)
		{
			case ENCR_AES_CBC:
			case ENCR_AES_CTR:
			case ENCR_CAMELLIA_CBC:
			case ENCR_CAMELLIA_CTR:
			case ENCR_AES_CCM_ICV8:
			case ENCR_AES_CCM_ICV12:
			case ENCR_AES_CCM_ICV16:
			case ENCR_AES_GCM_ICV8:
			case ENCR_AES_GCM_ICV12:
			case ENCR_AES_GCM_ICV16:
			case ENCR_CAMELLIA_CCM_ICV8:
			case ENCR_CAMELLIA_CCM_ICV12:
			case ENCR_CAMELLIA_CCM_ICV16:
				/* we assume that we support all AES/Camellia sizes */
				add_algorithm(this, ENCRYPTION_ALGORITHM, encryption, 128);
				add_algorithm(this, ENCRYPTION_ALGORITHM, encryption, 192);
				add_algorithm(this, ENCRYPTION_ALGORITHM, encryption, 256);
				break;
			case ENCR_3DES:
				add_algorithm(this, ENCRYPTION_ALGORITHM, encryption, 0);
				break;
			case ENCR_DES:
				/* no, thanks */
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	enumerator = lib->crypto->create_signer_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &integrity, &plugin_name))
	{
		switch (integrity)
		{
			case AUTH_HMAC_SHA1_96:
			case AUTH_HMAC_SHA2_256_128:
			case AUTH_HMAC_SHA2_384_192:
			case AUTH_HMAC_SHA2_512_256:
			case AUTH_HMAC_MD5_96:
			case AUTH_AES_XCBC_96:
			case AUTH_AES_CMAC_96:
				add_algorithm(this, INTEGRITY_ALGORITHM, integrity, 0);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	enumerator = lib->crypto->create_prf_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &prf, &plugin_name))
	{
		switch (prf)
		{
			case PRF_HMAC_SHA1:
			case PRF_HMAC_SHA2_256:
			case PRF_HMAC_SHA2_384:
			case PRF_HMAC_SHA2_512:
			case PRF_HMAC_MD5:
			case PRF_AES128_XCBC:
			case PRF_AES128_CMAC:
				add_algorithm(this, PSEUDO_RANDOM_FUNCTION, prf, 0);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	enumerator = lib->crypto->create_dh_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &group, &plugin_name))
	{
		switch (group)
		{
			case MODP_NULL:
				/* only for testing purposes */
				break;
			case MODP_768_BIT:
				/* weak */
				break;
			case MODP_1024_BIT:
			case MODP_1536_BIT:
			case MODP_2048_BIT:
			case MODP_3072_BIT:
			case MODP_4096_BIT:
			case MODP_8192_BIT:
			case ECP_256_BIT:
			case ECP_384_BIT:
			case ECP_521_BIT:
			case MODP_1024_160:
			case MODP_2048_224:
			case MODP_2048_256:
			case ECP_192_BIT:
			case ECP_224_BIT:
				add_algorithm(this, DIFFIE_HELLMAN_GROUP, group, 0);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
}

/*
 * Describtion in header-file
 */
proposal_t *proposal_create_default(protocol_id_t protocol)
{
	private_proposal_t *this = (private_proposal_t*)proposal_create(protocol, 0);

	switch (protocol)
	{
		case PROTO_IKE:
			proposal_add_supported_ike(this);
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
	private_proposal_t *this;
	enumerator_t *enumerator;
	bool failed = TRUE;
	char *alg;

	this = (private_proposal_t*)proposal_create(protocol, 0);

	/* get all tokens, separated by '-' */
	enumerator = enumerator_create_token(algs, "-", " ");
	while (enumerator->enumerate(enumerator, &alg))
	{
		if (!add_string_algo(this, alg))
		{
			failed = TRUE;
			break;
		}
		failed = FALSE;
	}
	enumerator->destroy(enumerator);

	if (failed)
	{
		destroy(this);
		return NULL;
	}

	check_proposal(this);

	return &this->public;
}
