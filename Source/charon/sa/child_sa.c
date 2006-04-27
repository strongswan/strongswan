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

#include <netdb.h>

#include "child_sa.h"

#include <daemon.h>


typedef struct sa_policy_t sa_policy_t;

/**
 * Struct used to store information for a policy. This
 * is needed since we must provide all this information
 * for deleting a policy...
 */
struct sa_policy_t {
	
	/**
	 * Network on local side
	 */
	host_t *my_net;
	
	/**
	 * Network on remote side
	 */
	host_t *other_net;
	
	/**
	 * Number of bits for local network (subnet size)
	 */
	u_int8_t my_net_mask;
	
	/**
	 * Number of bits for remote network (subnet size)
	 */
	u_int8_t other_net_mask;
	
	/**
	 * Protocol for this policy, such as TCP/UDP/ICMP...
	 */
	int upper_proto;
};

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
	 * Local security parameter index for AH protocol, 0 if not used
	 */
	u_int32_t my_ah_spi;
	
	/**
	 * Local security parameter index for ESP protocol, 0 if not used
	 */
	u_int32_t my_esp_spi;
	
	/**
	 * Remote security parameter index for AH protocol, 0 if not used
	 */
	u_int32_t other_ah_spi;
	
	/**
	 * Remote security parameter index for ESP protocol, 0 if not used
	 */
	u_int32_t other_esp_spi;
	
	/**
	 * List containing policy_id_t objects 
	 */
	linked_list_t *policies;
	
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
				case PROTO_AH:
					/* do we already have an spi for AH?*/
					if (this->my_ah_spi == 0)
					{
						/* nope, get one */
						status = charon->kernel_interface->get_spi(
											charon->kernel_interface,
											this->me, this->other,
											PROTO_AH, FALSE,
											&(this->my_ah_spi));
					}
					/* update proposal */
					proposal->set_spi(proposal, PROTO_AH, (u_int64_t)this->my_ah_spi);
					break;
				case PROTO_ESP:
					/* do we already have an spi for ESP?*/
					if (this->my_esp_spi == 0)
					{
						/* nope, get one */
						status = charon->kernel_interface->get_spi(
											charon->kernel_interface,
											this->me, this->other,
											PROTO_ESP, FALSE,
											&(this->my_esp_spi));
					}
					/* update proposal */
					proposal->set_spi(proposal, PROTO_ESP, (u_int64_t)this->my_esp_spi);
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
		if (protocols[i] != PROTO_NONE)
		{
			
			/* now we have to decide which spi to use. Use self allocated, if "mine",
			 * or the one in the proposal, if not "mine" (others). */
			if (mine)
			{
				if (protocols[i] == PROTO_AH)
				{
					spi = this->my_ah_spi;
				}
				else
				{
					spi = this->my_esp_spi;
				}
			}
			else /* use proposals spi */
			{
				spi = proposal->get_spi(proposal, protocols[i]);
				if (protocols[i] == PROTO_AH)
				{
					this->other_ah_spi = spi;
				}
				else
				{
					this->other_esp_spi = spi;
				}
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
				this->logger->log_chunk(this->logger, PRIVATE, "key:", enc_key);
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
				this->logger->log_chunk(this->logger, PRIVATE, "key:", int_key);
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
				chunk_free(&enc_key);
			}
			if (int_algo != AUTH_UNDEFINED)
			{
				chunk_free(&int_key);
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

static status_t add_policies(private_child_sa_t *this, linked_list_t *my_ts_list, linked_list_t *other_ts_list)
{
	iterator_t *my_iter, *other_iter;
	traffic_selector_t *my_ts, *other_ts;
	
	/* iterate over both lists */
	my_iter = my_ts_list->create_iterator(my_ts_list, TRUE);
	other_iter = other_ts_list->create_iterator(other_ts_list, TRUE);
	while (my_iter->has_next(my_iter))
	{
		my_iter->current(my_iter, (void**)&my_ts);
		other_iter->reset(other_iter);
		while (other_iter->has_next(other_iter))
		{
			/* set up policies for every entry in my_ts_list to every entry in other_ts_list */
			int family;
			chunk_t from_addr;
			u_int16_t from_port, to_port;
			sa_policy_t *policy;
			status_t status;
			
			other_iter->current(other_iter, (void**)&other_ts);
			
			/* only set up policies if protocol matches */
			if (my_ts->get_protocol(my_ts) != other_ts->get_protocol(other_ts))
			{
				continue;
			}
			policy = malloc_thing(sa_policy_t);
			policy->upper_proto = my_ts->get_protocol(my_ts);
		
			/* calculate net and ports for local side */
			family = my_ts->get_type(my_ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
			from_addr = my_ts->get_from_address(my_ts);
			from_port = my_ts->get_from_port(my_ts);
			to_port = my_ts->get_to_port(my_ts);
			from_port = (from_port != to_port) ? 0 : from_port;
			policy->my_net = host_create_from_chunk(family, from_addr, from_port);
			policy->my_net_mask = my_ts->get_netmask(my_ts);
			chunk_free(&from_addr);
			
			/* calculate net and ports for remote side */
			family = other_ts->get_type(other_ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
			from_addr = other_ts->get_from_address(other_ts);
			from_port = other_ts->get_from_port(other_ts);
			to_port = other_ts->get_to_port(other_ts);
			from_port = (from_port != to_port) ? 0 : from_port;
			policy->other_net = host_create_from_chunk(family, from_addr, from_port);
			policy->other_net_mask = other_ts->get_netmask(other_ts);
			chunk_free(&from_addr);
	
			/* install 3 policies: out, in and forward */
			status = charon->kernel_interface->add_policy(charon->kernel_interface,
					this->me, this->other,
					policy->my_net, policy->other_net,
					policy->my_net_mask, policy->other_net_mask,
					XFRM_POLICY_OUT, policy->upper_proto,
					this->my_ah_spi, this->my_esp_spi,
					this->reqid);
	
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other, this->me,
					policy->other_net, policy->my_net,
					policy->other_net_mask, policy->my_net_mask,
					XFRM_POLICY_IN, policy->upper_proto,
					this->my_ah_spi, this->my_esp_spi,
					this->reqid);
	
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other, this->me,
					policy->other_net, policy->my_net,
					policy->other_net_mask, policy->my_net_mask,
					XFRM_POLICY_FWD, policy->upper_proto,
					this->my_ah_spi, this->my_esp_spi,
					this->reqid);
			
			if (status != SUCCESS)
			{
				my_iter->destroy(my_iter);
				other_iter->destroy(other_iter);
				policy->my_net->destroy(policy->my_net);
				policy->other_net->destroy(policy->other_net);
				free(policy);
				return status;
			}
			
			/* add it to the policy list, since we want to know which policies we own */
			this->policies->insert_last(this->policies, policy);
		}
	}

	my_iter->destroy(my_iter);
	other_iter->destroy(other_iter);
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.log_status.
 */
static void log_status(private_child_sa_t *this, logger_t *logger, char* name)
{
	iterator_t *iterator;
	sa_policy_t *policy;
	struct protoent *proto;
	char proto_buf[8] = "";
	char *proto_name = proto_buf;
	
	if (logger == NULL)
	{
		logger = this->logger;
	}
	logger->log(logger, CONTROL|LEVEL1, "\"%s\":   protected with ESP (0x%x/0x%x), AH (0x%x,0x%x):",
				name,
				htonl(this->my_esp_spi), htonl(this->other_esp_spi), 
				htonl(this->my_ah_spi), htonl(this->other_ah_spi));
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&policy);
		if (policy->upper_proto)
		{
			proto = getprotobynumber(policy->upper_proto);
			if (proto)
			{
				proto_name = proto->p_name;
			}
			else
			{
				snprintf(proto_buf, sizeof(proto_buf), "<%d>", policy->upper_proto);
			}
		}
		logger->log(logger, CONTROL, "\"%s\":     %s/%d==%s==%s/%d",
					name,
					policy->my_net->get_address(policy->my_net), policy->my_net_mask,
					proto_name,
					policy->other_net->get_address(policy->other_net), policy->other_net_mask);
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	/* delete all policys in the kernel */
	sa_policy_t *policy;
	while (this->policies->remove_last(this->policies, (void**)&policy) == SUCCESS)
	{
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->me, this->other,
											 policy->my_net, policy->other_net,
											 policy->my_net_mask, policy->other_net_mask,
											 XFRM_POLICY_OUT, policy->upper_proto);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->other, this->me,
											 policy->other_net, policy->my_net,
											 policy->other_net_mask, policy->my_net_mask,
											 XFRM_POLICY_IN, policy->upper_proto);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->other, this->me,
											 policy->other_net, policy->my_net,
											 policy->other_net_mask, policy->my_net_mask,
											 XFRM_POLICY_FWD, policy->upper_proto);
		
		policy->my_net->destroy(policy->my_net);
		policy->other_net->destroy(policy->other_net);
		free(policy);
	}
	this->policies->destroy(this->policies);
	
	/* delete SAs in the kernel, if they are set up */
	if (this->my_ah_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->other, this->my_ah_spi, PROTO_AH);
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me, this->other_ah_spi, PROTO_AH);
	}
	if (this->my_esp_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->other, this->my_esp_spi, PROTO_ESP);
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me, this->other_esp_spi, PROTO_ESP);
	}
	free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(host_t *me, host_t* other)
{
	static u_int32_t reqid = 0xc0000000;
	private_child_sa_t *this = malloc_thing(private_child_sa_t);

	/* public functions */
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))update;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*))add_policies;
	this->public.log_status = (void (*)(child_sa_t*, logger_t*, char*))log_status;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->logger = logger_manager->get_logger(logger_manager, CHILD_SA);
	this->me = me;
	this->other = other;
	this->my_ah_spi = 0;
	this->my_esp_spi = 0;
	this->other_ah_spi = 0;
	this->other_esp_spi = 0;
	this->reqid = reqid++;
	this->policies = linked_list_create();
	
	return (&this->public);
}
