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
	 * IP of this peer
	 */
	host_t *me;
	
	/**
	 * IP of other peer
	 */
	host_t *other;
	
	/**
	 * Security parameter index for AH protocol, 0 if not used
	 */
	u_int32_t ah_spi;
	
	/**
	 * Security parameter index for ESP protocol, 0 if not used
	 */
	u_int32_t esp_spi;
	
	/**
	 * reqid used for this child_sa
	 */
	u_int32_t reqid;
	
	/**
	 * CHILD_SAs own logger
	 */
	logger_t *logger;
};

/**
 * Implements child_sa_t.alloc
 */
static status_t alloc(private_child_sa_t *this, linked_list_t *proposals)
{
	protocol_id_t protocols[2];
	iterator_t *iterator;
	proposal_t *proposal;
	status_t status;
	u_int i;
	
	/* iterator through proposals */
	iterator = proposals->create_iterator(proposals, TRUE);
	while(iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		proposal->get_protocols(proposal, protocols);
	
		/* check all protocols */
		for (i = 0; i<2; i++)
		{
			switch (protocols[i])
			{
				case AH:
					/* do we already have an spi for AH?*/
					if (this->ah_spi == 0)
					{
						/* nope, get one */
						status = charon->kernel_interface->get_spi(
											charon->kernel_interface,
											this->me, this->other,
											AH, FALSE,
											&(this->ah_spi));
					}
					/* update proposal */
					proposal->set_spi(proposal, AH, (u_int64_t)this->ah_spi);
					break;
				case ESP:
					/* do we already have an spi for ESP?*/
					if (this->esp_spi == 0)
					{
						/* nope, get one */
						status = charon->kernel_interface->get_spi(
											charon->kernel_interface,
											this->me, this->other,
											ESP, FALSE,
											&(this->esp_spi));
					}
					/* update proposal */
					proposal->set_spi(proposal, ESP, (u_int64_t)this->esp_spi);
					break;
				default:
					break;
			}
			if (status != SUCCESS)
			{
				iterator->destroy(iterator);
				return FAILED;
			}
		}
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

static status_t install(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus, bool mine)
{
	protocol_id_t protocols[2];
	u_int32_t spi;
	encryption_algorithm_t enc_algo;
	integrity_algorithm_t int_algo;
	chunk_t enc_key, int_key;
	algorithm_t *algo;
	crypter_t *crypter;
	signer_t *signer;
	size_t key_size;
	host_t *src;
	host_t *dst;
	status_t status;
	u_int i;
	
	/* we must assign the roles to correctly set up the SAs */
 	if (mine)
 	{
 		src = this->me;
 		dst = this->other;
 	}
 	else
 	{
 		dst = this->me;
 		src = this->other;
 	}
	
	proposal->get_protocols(proposal, protocols);
	/* derive keys in order as protocols appear */
	for (i = 0; i<2; i++)
	{
		if (protocols[i] != UNDEFINED_PROTOCOL_ID)
		{
			
			/* now we have to decide which spi to use. Use self allocated, if "mine",
			 * or the one in the proposal, if not "mine" (others). */
			if (mine)
			{
				if (protocols[i] == AH)
				{
					spi = this->ah_spi;
				}
				else
				{
					spi = this->esp_spi;
				}
			}
			else /* use proposals spi */
			{
				spi = proposal->get_spi(proposal, protocols[i]);
			}
			
			/* derive encryption key first */
			if (proposal->get_algorithm(proposal, protocols[i], ENCRYPTION_ALGORITHM, &algo))
			{
				enc_algo = algo->algorithm;
				this->logger->log(this->logger, CONTROL|LEVEL1, "%s for %s: using %s %s, ",
								  mapping_find(protocol_id_m, protocols[i]),
								  mine ? "me" : "other",
								  mapping_find(transform_type_m, ENCRYPTION_ALGORITHM),
								  mapping_find(encryption_algorithm_m, enc_algo));
				
				/* we must create a (unused) crypter, since its the only way to get the size
				 * of the key. This is not so nice, since charon must support all algorithms
				 * the kernel supports...
				 * TODO: build something of a encryption algorithm lookup function 
				 */
				crypter = crypter_create(enc_algo, algo->key_size);
				key_size = crypter->get_key_size(crypter);
				crypter->destroy(crypter);
				prf_plus->allocate_bytes(prf_plus, key_size, &enc_key);
				this->logger->log_chunk(this->logger, PRIVATE, "key:", &enc_key);
			}
			else
			{
				enc_algo = ENCR_UNDEFINED;
			}
			
			/* derive integrity key */
			if (proposal->get_algorithm(proposal, protocols[i], INTEGRITY_ALGORITHM, &algo))
			{
				int_algo = algo->algorithm;
				this->logger->log(this->logger, CONTROL|LEVEL1, "%s for %s: using %s %s,",
								  mapping_find(protocol_id_m, protocols[i]),
								  mine ? "me" : "other",
								  mapping_find(transform_type_m, INTEGRITY_ALGORITHM),
								  mapping_find(integrity_algorithm_m, algo->algorithm));
				
				signer = signer_create(int_algo);
				key_size = signer->get_key_size(signer);
				signer->destroy(signer);
				prf_plus->allocate_bytes(prf_plus, key_size, &int_key);
				this->logger->log_chunk(this->logger, PRIVATE, "key:", &int_key);
			}
			else
			{
				int_algo = AUTH_UNDEFINED;
			}
			/* send keys down to kernel */
			this->logger->log(this->logger, CONTROL|LEVEL1, 
							  "installing 0x%.8x for %s, src %s dst %s",
							  ntohl(spi), mapping_find(protocol_id_m, protocols[i]), 
							  src->get_address(src), dst->get_address(dst));
			status = charon->kernel_interface->add_sa(charon->kernel_interface,
													  src, dst,
													  spi, protocols[i],
													  this->reqid,
													  enc_algo, enc_key,
													  int_algo, int_key, mine);
			/* clean up for next round */
			if (enc_algo != ENCR_UNDEFINED)
			{
				allocator_free_chunk(&enc_key);
			}
			if (int_algo != AUTH_UNDEFINED)
			{
				allocator_free_chunk(&int_key);
			}
			
			if (status != SUCCESS)
			{
				return FAILED;
			}
			
			
		}
	}
	return SUCCESS;
}

static status_t add(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus)
{
	linked_list_t *list;
	
	/* install others (initiators) SAs*/
	if (install(this, proposal, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* get SPIs for our SAs */
	list = linked_list_create();
	list->insert_last(list, proposal);
	if (alloc(this, list) != SUCCESS)
	{
		list->destroy(list);
		return FAILED;
	}
	list->destroy(list);
	
	/* install our (responders) SAs */
	if (install(this, proposal, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	
	return SUCCESS;
}

static status_t update(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus)
{
	/* install our (initator) SAs */
	if (install(this, proposal, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	/* install his (responder) SAs */
	if (install(this, proposal, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	
	return SUCCESS;
}

static u_int8_t get_mask(chunk_t start, chunk_t end)
{
	int byte, bit, mask = 0;
	
	if (start.len != end.len)
	{
		return 0;
	}
	for (byte = 0; byte < start.len; byte++)
	{
		for (bit = 7; bit >= 0; bit--)
		{
			if ((*(start.ptr + byte) | (1<<bit)) ==
				(*(end.ptr + byte) | (1<<bit)))
			{
				mask++;
			}
			else
			{
				return mask;
			}
		}
	}
	return start.len * 8;
}

static status_t add_policy(private_child_sa_t *this, linked_list_t *my_ts, linked_list_t *other_ts)
{
	traffic_selector_t *local_ts, *remote_ts;
	host_t *my_net, *other_net;
	u_int8_t my_mask, other_mask;
	int family;
	chunk_t from_addr, to_addr;
	u_int16_t from_port, to_port;
	status_t status;
	
	my_ts->get_first(my_ts, (void**)&local_ts);
	other_ts->get_first(other_ts, (void**)&remote_ts);
		
	family = local_ts->get_type(local_ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
	from_addr = local_ts->get_from_address(local_ts);
	to_addr = local_ts->get_to_address(local_ts);
	from_port = local_ts->get_from_port(local_ts);
	to_port = local_ts->get_to_port(local_ts);
	if (from_port != to_port)
	{
		from_port = 0;
	}
	my_net = host_create_from_chunk(family, from_addr, from_port);
	my_mask = get_mask(from_addr, to_addr);
	allocator_free_chunk(&from_addr);
	allocator_free_chunk(&to_addr);
	
	family = remote_ts->get_type(remote_ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
	from_addr = remote_ts->get_from_address(remote_ts);
	to_addr = remote_ts->get_to_address(remote_ts);
	from_port = remote_ts->get_from_port(remote_ts);
	to_port = remote_ts->get_to_port(remote_ts);
	if (from_port != to_port)
	{
		from_port = 0;
	}
	other_net = host_create_from_chunk(family, from_addr, from_port);
	other_mask = get_mask(from_addr, to_addr);
	allocator_free_chunk(&from_addr);
	allocator_free_chunk(&to_addr);
	
	status = charon->kernel_interface->add_policy(charon->kernel_interface,
										this->me, this->other,
										my_net, other_net,
										my_mask, other_mask,
										XFRM_POLICY_OUT,
										0, this->ah_spi, this->esp_spi,
										this->reqid);
	
	status |= charon->kernel_interface->add_policy(charon->kernel_interface,
										 this->other, this->me,
										 other_net, my_net,
										 other_mask, my_mask,
										 XFRM_POLICY_IN,
										 0, this->ah_spi, this->esp_spi,
										 this->reqid);
	
	status |= charon->kernel_interface->add_policy(charon->kernel_interface,
										 this->other, this->me,
										 other_net, my_net,
										 other_mask, my_mask,
										 XFRM_POLICY_FWD,
										 0, this->ah_spi, this->esp_spi,
										 this->reqid);
	
	return status;
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
child_sa_t * child_sa_create(host_t *me, host_t* other)
{
	static u_int32_t reqid = 123;
	private_child_sa_t *this = allocator_alloc_thing(private_child_sa_t);

	/* public functions */
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))update;
	this->public.add_policy = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*))add_policy;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->logger = charon->logger_manager->create_logger(charon->logger_manager, CHILD_SA, NULL);
	this->me = me;
	this->other = other;
	this->ah_spi = 0;
	this->esp_spi = 0;
	this->reqid = reqid++;
	
	return (&this->public);
}
