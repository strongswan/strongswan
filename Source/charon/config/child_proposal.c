/**
 * @file child_proposal.c
 * 
 * @brief Implementation of child_proposal_t.
 * 
 */

/*
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
 */

#include "child_proposal.h"

#include <utils/linked_list.h>
#include <utils/allocator.h>
#include <utils/identification.h>
#include <utils/logger.h>


/** 
 * String mappings for protocol_id_t.
 */
mapping_t protocol_id_m[] = {
	{UNDEFINED_PROTOCOL_ID, "UNDEFINED_PROTOCOL_ID"},
	{IKE, "IKE"},
	{AH, "AH"},
	{ESP, "ESP"},
	{MAPPING_END, NULL}
};

/** 
 * String mappings for transform_type_t.
 */
mapping_t transform_type_m[] = {
	{UNDEFINED_TRANSFORM_TYPE, "UNDEFINED_TRANSFORM_TYPE"},
	{ENCRYPTION_ALGORITHM, "ENCRYPTION_ALGORITHM"},
	{PSEUDO_RANDOM_FUNCTION, "PSEUDO_RANDOM_FUNCTION"},
	{INTEGRITY_ALGORITHM, "INTEGRITY_ALGORITHM"},
	{DIFFIE_HELLMAN_GROUP, "DIFFIE_HELLMAN_GROUP"},
	{EXTENDED_SEQUENCE_NUMBERS, "EXTENDED_SEQUENCE_NUMBERS"},
	{MAPPING_END, NULL}
};

/** 
 * String mappings for extended_sequence_numbers_t.
 */
mapping_t extended_sequence_numbers_m[] = {
	{NO_EXT_SEQ_NUMBERS, "NO_EXT_SEQ_NUMBERS"},
	{EXT_SEQ_NUMBERS, "EXT_SEQ_NUMBERS"},
	{MAPPING_END, NULL}
};


typedef struct protocol_proposal_t protocol_proposal_t;

/**
 * substructure which holds all data algos for a specific protocol
 */
struct protocol_proposal_t {
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
	chunk_t spi;
};


typedef struct private_child_proposal_t private_child_proposal_t;

/**
 * Private data of an child_proposal_t object
 */
struct private_child_proposal_t {

	/**
	 * Public part
	 */
	child_proposal_t public;
	
	/**
	 * number of this proposal, as used in the payload
	 */
	u_int8_t number;
	
	/**
	 * list of protocol_proposal_t's
	 */
	linked_list_t *protocol_proposals;
};

/**
 * Look up a protocol_proposal, or create one if necessary...
 */
static protocol_proposal_t *get_protocol_proposal(private_child_proposal_t *this, protocol_id_t proto, bool create)
{
	protocol_proposal_t *proto_proposal = NULL, *current_proto_proposal;;
	iterator_t *iterator;
	 
	/* find our protocol in the proposals */
	iterator = this->protocol_proposals->create_iterator(this->protocol_proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&current_proto_proposal);
		if (current_proto_proposal->protocol == proto)
		{
			proto_proposal = current_proto_proposal;
			break;
		}
	}
	iterator->destroy(iterator);

	if (!proto_proposal && create)
	{
		/* nope, create a new one */
		proto_proposal = allocator_alloc_thing(protocol_proposal_t);
		proto_proposal->protocol = proto;
		proto_proposal->encryption_algos = linked_list_create();
		proto_proposal->integrity_algos = linked_list_create();
		proto_proposal->prf_algos = linked_list_create();
		proto_proposal->dh_groups = linked_list_create();
		proto_proposal->esns = linked_list_create();
		if (proto == IKE)
		{
			proto_proposal->spi.len = 8;
		}
		else
		{
			proto_proposal->spi.len = 4;
		}
		proto_proposal->spi.ptr = allocator_alloc(proto_proposal->spi.len);
		/* add to the list */
		this->protocol_proposals->insert_last(this->protocol_proposals, (void*)proto_proposal);
	}
	return proto_proposal;
}

/**
 * Add algorithm/keysize to a algorithm list
 */
static void add_algo(linked_list_t *list, u_int8_t algo, size_t key_size)
{
	algorithm_t *algo_key = allocator_alloc_thing(algorithm_t);
	
	algo_key->algorithm = algo;
	algo_key->key_size = key_size;
	list->insert_last(list, (void*)algo_key);
}

/**
 * Implements child_proposal_t.add_algorithm
 */
static void add_algorithm(private_child_proposal_t *this, protocol_id_t proto, transform_type_t type, u_int16_t algo, size_t key_size)
{
	protocol_proposal_t *proto_proposal = get_protocol_proposal(this, proto, TRUE);
	
	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			add_algo(proto_proposal->encryption_algos, algo, key_size);
			break;
		case INTEGRITY_ALGORITHM:
			add_algo(proto_proposal->integrity_algos, algo, key_size);
			break;
		case PSEUDO_RANDOM_FUNCTION:
			add_algo(proto_proposal->prf_algos, algo, key_size);
			break;
		case DIFFIE_HELLMAN_GROUP:
			add_algo(proto_proposal->dh_groups, algo, 0);
			break;
		case EXTENDED_SEQUENCE_NUMBERS:
			add_algo(proto_proposal->esns, algo, 0);
			break;
		default:
			break;
	}
}

/**
 * Implements child_proposal_t.get_algorithm.
 */
static bool get_algorithm(private_child_proposal_t *this, protocol_id_t proto, transform_type_t type, algorithm_t** algo)
{
	linked_list_t * list;
	protocol_proposal_t *proto_proposal = get_protocol_proposal(this, proto, FALSE);
	
	if (proto_proposal == NULL)
	{
		return FALSE;
	}
	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			list = proto_proposal->encryption_algos;
			break;
		case INTEGRITY_ALGORITHM:
			list = proto_proposal->integrity_algos;
			break;
		case PSEUDO_RANDOM_FUNCTION:
			list = proto_proposal->prf_algos;
			break;
		case DIFFIE_HELLMAN_GROUP:
			list = proto_proposal->dh_groups;
			break;
		case EXTENDED_SEQUENCE_NUMBERS:
			list = proto_proposal->esns;
			break;
		default:
			return FALSE;
	}
	if (list->get_first(list, (void**)algo) != SUCCESS)
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Implements child_proposal_t.create_algorithm_iterator.
 */
static iterator_t *create_algorithm_iterator(private_child_proposal_t *this, protocol_id_t proto, transform_type_t type)
{
	protocol_proposal_t *proto_proposal = get_protocol_proposal(this, proto, FALSE);
	if (proto_proposal == NULL)
	{
		return NULL;
	}
	
	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			return proto_proposal->encryption_algos->create_iterator(proto_proposal->encryption_algos, TRUE);
		case INTEGRITY_ALGORITHM:
			return proto_proposal->integrity_algos->create_iterator(proto_proposal->integrity_algos, TRUE);
		case PSEUDO_RANDOM_FUNCTION:
			return proto_proposal->prf_algos->create_iterator(proto_proposal->prf_algos, TRUE);
		case DIFFIE_HELLMAN_GROUP:
			return proto_proposal->dh_groups->create_iterator(proto_proposal->dh_groups, TRUE);
		case EXTENDED_SEQUENCE_NUMBERS:
			return proto_proposal->esns->create_iterator(proto_proposal->esns, TRUE);
		default:
			break;
	}
	return NULL;
}

/**
 * Find a matching alg/keysize in two linked lists
 */
static bool select_algo(linked_list_t *first, linked_list_t *second, bool *add, u_int16_t *alg, size_t *key_size)
{
	iterator_t *first_iter, *second_iter;
	algorithm_t *first_alg, *second_alg;
	
	/* if in both are zero algorithms specified, we HAVE a match */
	if (first->get_count(first) == 0 && second->get_count(second) == 0)
	{
		*add = FALSE;
		return TRUE;
	}
	
	first_iter = first->create_iterator(first, TRUE);
	second_iter = second->create_iterator(second, TRUE);
	/* compare algs, order of algs in "first" is preferred */
	while (first_iter->has_next(first_iter))
	{
		first_iter->current(first_iter, (void**)&first_alg);
		second_iter->reset(second_iter);
		while (second_iter->has_next(second_iter))
		{
			second_iter->current(second_iter, (void**)&second_alg);
			if (first_alg->algorithm == second_alg->algorithm &&
				first_alg->key_size == second_alg->key_size)
			{
				/* ok, we have an algorithm */
				*alg = first_alg->algorithm;
				*key_size = first_alg->key_size;
				*add = TRUE;
				first_iter->destroy(first_iter);
				second_iter->destroy(second_iter);
				return TRUE;
			}
		}
	}
	/* no match in all comparisons */
	first_iter->destroy(first_iter);
	second_iter->destroy(second_iter);
	return FALSE;
}

/**
 * Implements child_proposal_t.select.
 */
static child_proposal_t *select_proposal(private_child_proposal_t *this, private_child_proposal_t *other)
{
	child_proposal_t *selected;
	u_int16_t algo;
	size_t key_size;
	iterator_t *iterator;
	protocol_proposal_t *this_prop, *other_prop;
	protocol_id_t proto;
	bool add;
	
	/* empty proposal? no match */
	if (this->protocol_proposals->get_count(this->protocol_proposals) == 0 ||
		other->protocol_proposals->get_count(other->protocol_proposals) == 0)
	{
		return NULL;
	}
	/* they MUST have the same amount of protocols */
	if (this->protocol_proposals->get_count(this->protocol_proposals) !=
		other->protocol_proposals->get_count(other->protocol_proposals))
	{
		return NULL;
	}
	
	selected = child_proposal_create(this->number);
	
	/* iterate over supplied proposals */
	iterator = other->protocol_proposals->create_iterator(other->protocol_proposals, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&other_prop);
		/* get the proposal with the same protocol */
		proto = other_prop->protocol;
		this_prop = get_protocol_proposal(this, proto, FALSE);
		
		if (this_prop == NULL)
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
		
		/* select encryption algorithm */
		if (select_algo(this_prop->encryption_algos, other_prop->encryption_algos, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, proto, ENCRYPTION_ALGORITHM, algo, key_size);
			}
		}
		else
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
		/* select integrity algorithm */
		if (select_algo(this_prop->integrity_algos, other_prop->integrity_algos, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, proto, INTEGRITY_ALGORITHM, algo, key_size);
			}
		}
		else
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
		/* select prf algorithm */
		if (select_algo(this_prop->prf_algos, other_prop->prf_algos, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, proto, PSEUDO_RANDOM_FUNCTION, algo, key_size);
			}
		}
		else
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
		/* select a DH-group */
		if (select_algo(this_prop->dh_groups, other_prop->dh_groups, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, proto, DIFFIE_HELLMAN_GROUP, algo, 0);
			}
		}
		else
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
		/* select if we use ESNs */
		if (select_algo(this_prop->esns, other_prop->esns, &add, &algo, &key_size))
		{
			if (add)
			{
				selected->add_algorithm(selected, proto, EXTENDED_SEQUENCE_NUMBERS, algo, 0);
			}
		}
		else
		{
			iterator->destroy(iterator);
			selected->destroy(selected);
			return NULL;
		}
	}
	iterator->destroy(iterator);
	/* everything matched, return new proposal */
	return selected;
}

/**
 * Implements child_proposal_t.get_number.
 */
static u_int8_t get_number(private_child_proposal_t *this)
{
	return this->number;
}

/**
 * Implements child_proposal_t.get_protocols.
 */
static void get_protocols(private_child_proposal_t *this, protocol_id_t ids[2])
{
	iterator_t *iterator = this->protocol_proposals->create_iterator(this->protocol_proposals, TRUE);
	u_int i = 0;
	
	ids[0] = UNDEFINED_PROTOCOL_ID;
	ids[1] = UNDEFINED_PROTOCOL_ID;
	while (iterator->has_next(iterator))
	{
		protocol_proposal_t *proto_prop;
		iterator->current(iterator, (void**)&proto_prop);
		ids[i++] = proto_prop->protocol;
		if (i>1)
		{
			/* should not happen, but who knows */
			break;
		}
	}
	iterator->destroy(iterator);
}

/**
 * Implements child_proposal_t.set_spi.
 */
static void set_spi(private_child_proposal_t *this, protocol_id_t proto, u_int64_t spi)
{
	protocol_proposal_t *proto_proposal = get_protocol_proposal(this, proto, FALSE);
	if (proto_proposal)
	{
		if (proto == IKE)
		{
			*((u_int32_t*)proto_proposal->spi.ptr) = (u_int32_t)spi;
		}
		else
		{
			*((u_int64_t*)proto_proposal->spi.ptr) = spi;
		}
		
	}
}

/**
 * Implements child_proposal_t.get_spi.
 */
static u_int64_t get_spi(private_child_proposal_t *this, protocol_id_t proto)
{
	protocol_proposal_t *proto_proposal = get_protocol_proposal(this, proto, FALSE);
	if (proto_proposal)
	{
		if (proto == IKE)
		{
			return (u_int64_t)*((u_int32_t*)proto_proposal->spi.ptr);
		}
		else
		{
			return *((u_int64_t*)proto_proposal->spi.ptr);
		}
	}
	return 0;
}

/**
 * Frees all list items and destroys the list
 */
static void free_algo_list(linked_list_t *list)
{
	algorithm_t *algo;
	
	while(list->get_count(list) > 0)
	{
		list->remove_last(list, (void**)&algo);
		allocator_free(algo);
	}
	list->destroy(list);
}

/**
 * Implements child_proposal_t.destroy.
 */
static void destroy(private_child_proposal_t *this)
{
	while(this->protocol_proposals->get_count(this->protocol_proposals) > 0)
	{
		protocol_proposal_t *proto_prop;
		this->protocol_proposals->remove_last(this->protocol_proposals, (void**)&proto_prop);
		
		free_algo_list(proto_prop->encryption_algos);
		free_algo_list(proto_prop->integrity_algos);
		free_algo_list(proto_prop->prf_algos);
		free_algo_list(proto_prop->dh_groups);
		free_algo_list(proto_prop->esns);
		
		allocator_free(proto_prop->spi.ptr);
		allocator_free(proto_prop);
	}
	this->protocol_proposals->destroy(this->protocol_proposals);
	
	allocator_free(this);
}

/*
 * Describtion in header-file
 */
child_proposal_t *child_proposal_create(u_int8_t number)
{
	private_child_proposal_t *this = allocator_alloc_thing(private_child_proposal_t);
	
	this->public.add_algorithm = (void (*)(child_proposal_t*,protocol_id_t,transform_type_t,u_int16_t,size_t))add_algorithm;
	this->public.create_algorithm_iterator = (iterator_t* (*)(child_proposal_t*,protocol_id_t,transform_type_t))create_algorithm_iterator;
	this->public.get_algorithm = (bool (*)(child_proposal_t*,protocol_id_t,transform_type_t,algorithm_t**))get_algorithm;
	this->public.select = (child_proposal_t* (*)(child_proposal_t*,child_proposal_t*))select_proposal;
	this->public.get_number = (u_int8_t (*)(child_proposal_t*))get_number;
	this->public.get_protocols = (void(*)(child_proposal_t *this, protocol_id_t ids[2]))get_protocols;
	this->public.set_spi = (void(*)(child_proposal_t*,protocol_id_t,u_int64_t spi))set_spi;
	this->public.get_spi = (u_int64_t(*)(child_proposal_t*,protocol_id_t))get_spi;
	this->public.destroy = (void(*)(child_proposal_t*))destroy;
	
	/* init private members*/
	this->number = number;
	this->protocol_proposals = linked_list_create();
	
	return (&this->public);
}
