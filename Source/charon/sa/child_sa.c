/**
 * @file child_sa.c
 *
 * @brief Implementation of child_sa_t.
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

#include "child_sa.h"


#include <utils/allocator.h>
#include <daemon.h>


typedef struct private_child_sa_t private_child_sa_t;

/**
 * Private data of a child_sa_t object.
 */
struct private_child_sa_t {
	/**
	 * Public interface of child_sa_t.
	 */
	child_sa_t public;
	
	/**
	 * CHILD_SAs own logger
	 */
	logger_t *logger;
	
	/**
	 * Protocols used in this SA
	 */
	protocol_id_t protocols[2];
};


/**
 * Implementation of child_sa_t.get_spi.
 */
static u_int32_t get_spi(private_child_sa_t *this)
{
	return 0;
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	charon->logger_manager->destroy_logger(charon->logger_manager, this->logger);
	allocator_free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(child_proposal_t *proposal, prf_plus_t *prf_plus)
{
	private_child_sa_t *this = allocator_alloc_thing(private_child_sa_t);
	u_int i;

	/* public functions */
	this->public.get_spi = (u_int32_t(*)(child_sa_t*))get_spi;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, CHILD_SA, NULL);
	proposal->get_protocols(proposal, this->protocols);
	
	/* derive keys */
	for (i = 0; i<2; i++)
	{
		if (this->protocols[i] != UNDEFINED_PROTOCOL_ID)
		{
			algorithm_t *algo;
			chunk_t key;
			
			/* get encryption key */
			if (proposal->get_algorithm(proposal, this->protocols[i], ENCRYPTION_ALGORITHM, &algo))
			{
				this->logger->log(this->logger, CONTROL|LEVEL1, "%s: using %s %s, ",
								  mapping_find(protocol_id_m, this->protocols[i]),
								  mapping_find(transform_type_m, ENCRYPTION_ALGORITHM),
								  mapping_find(encryption_algorithm_m, algo->algorithm));
				
				prf_plus->allocate_bytes(prf_plus, algo->key_size, &key);
				this->logger->log_chunk(this->logger, PRIVATE, "key:", &key);
				allocator_free_chunk(&key);
			}
			
			/* get integrity key */
			if (proposal->get_algorithm(proposal, this->protocols[i], INTEGRITY_ALGORITHM, &algo))
			{
				this->logger->log(this->logger, CONTROL|LEVEL1, "%s: using %s %s,",
								  mapping_find(protocol_id_m, this->protocols[i]),
								  mapping_find(transform_type_m, INTEGRITY_ALGORITHM),
								  mapping_find(integrity_algorithm_m, algo->algorithm));
				
				prf_plus->allocate_bytes(prf_plus, algo->key_size, &key);
				this->logger->log_chunk(this->logger, PRIVATE, "key:", &key);
				allocator_free_chunk(&key);
			}
		}
	}
	
	return (&this->public);
}
