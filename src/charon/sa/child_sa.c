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
	
	struct {
		/** subnet address behind peer peer */
		host_t *net;
		/** netmask used for net */
		u_int8_t net_mask;
	} me, other;
	
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
	
	struct {
		/** address of peer */
		host_t *addr;
		/** actual used SPI, 0 if unused */
		u_int32_t spi;
	} me, other;
	
	/**
	 * Protocol used to protect this SA, ESP|AH
	 */
	protocol_id_t protocol;
	
	/**
	 * List containing sa_policy_t objects 
	 */
	linked_list_t *policies;
	
	/**
	 * reqid used for this child_sa
	 */
	u_int32_t reqid;
	
	/**
	 * Lifetime before rekeying
	 */
	u_int32_t soft_lifetime;
	
	/**
	 * Lifetime before delete
	 */
	u_int32_t hard_lifetime;
	
	/**
	 * CHILD_SAs own logger
	 */
	logger_t *logger;
};

/**
 * Implements child_sa_t.get_reqid
 */
static u_int32_t get_reqid(private_child_sa_t *this)
{
	return this->reqid;
}
	
/**
 * Implements child_sa_t.get_spi
 */
u_int32_t get_spi(private_child_sa_t *this, bool inbound)
{
	if (inbound)
	{
		return this->me.spi;
	}
	return this->other.spi;
}

/**
 * Implements child_sa_t.get_protocol
 */
protocol_id_t get_protocol(private_child_sa_t *this)
{
	return this->protocol;
}

/**
 * Implements child_sa_t.alloc
 */
static status_t alloc(private_child_sa_t *this, linked_list_t *proposals)
{
	protocol_id_t protocol;
	iterator_t *iterator;
	proposal_t *proposal;
	status_t status;
	
	/* iterator through proposals */
	iterator = proposals->create_iterator(proposals, TRUE);
	while(iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		protocol = proposal->get_protocol(proposal);
		
		status = charon->kernel_interface->get_spi(
					charon->kernel_interface,
					this->other.addr, this->me.addr,
					protocol, this->reqid,
					&this->me.spi);
		
		if (status != SUCCESS)
		{
			iterator->destroy(iterator);
			return FAILED;
		}
		/* update proposal */
		proposal->set_spi(proposal, (u_int64_t)this->me.spi);
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

static status_t install(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus, bool mine)
{
	u_int32_t spi;
	algorithm_t *enc_algo, *int_algo;
	algorithm_t enc_algo_none = {ENCR_UNDEFINED, 0};
	algorithm_t int_algo_none = {AUTH_UNDEFINED, 0};
	host_t *src;
	host_t *dst;
	status_t status;
	
	/* we must assign the roles to correctly set up the SAs */
 	if (mine)
	{
		dst = this->me.addr;
		src = this->other.addr;
 	}
 	else
	{
		src = this->me.addr;
		dst = this->other.addr;
 	}
	
	this->protocol = proposal->get_protocol(proposal);
	
	/* now we have to decide which spi to use. Use self allocated, if "mine",
	 * or the one in the proposal, if not "mine" (others). */
	if (mine)
	{
		spi = this->me.spi;
	}
	else
	{
		spi = proposal->get_spi(proposal);
		this->other.spi = spi;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "Adding %s %s SA",
					  mine ? "inbound" : "outbound",
					  mapping_find(protocol_id_m, this->protocol));
	
	/* select encryption algo */
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &enc_algo))
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "  using %s for encryption",
							mapping_find(encryption_algorithm_m, enc_algo->algorithm));
	}
	else
	{
		enc_algo = &enc_algo_none;
	}
	
	/* select integrity algo */
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &int_algo))
	{
		this->logger->log(this->logger, CONTROL|LEVEL2, "  using %s for integrity",
						  mapping_find(integrity_algorithm_m, int_algo->algorithm));
	}
	else
	{
		int_algo = &int_algo_none;
	}
	
	/* send SA down to the kernel */
	this->logger->log(this->logger, CONTROL|LEVEL2,
						"  SPI 0x%.8x, src %s dst %s",
						ntohl(spi), src->get_address(src), dst->get_address(dst));
	status = charon->kernel_interface->add_sa(charon->kernel_interface,
												src, dst,
												spi, this->protocol,
												this->reqid,
												mine ? 0 : this->soft_lifetime,
												this->hard_lifetime,
												enc_algo, int_algo, prf_plus, mine);

	return status;
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
			policy->me.net = host_create_from_chunk(family, from_addr, from_port);
			policy->me.net_mask = my_ts->get_netmask(my_ts);
			chunk_free(&from_addr);
			
			/* calculate net and ports for remote side */
			family = other_ts->get_type(other_ts) == TS_IPV4_ADDR_RANGE ? AF_INET : AF_INET6;
			from_addr = other_ts->get_from_address(other_ts);
			from_port = other_ts->get_from_port(other_ts);
			to_port = other_ts->get_to_port(other_ts);
			from_port = (from_port != to_port) ? 0 : from_port;
			policy->other.net = host_create_from_chunk(family, from_addr, from_port);
			policy->other.net_mask = other_ts->get_netmask(other_ts);
			chunk_free(&from_addr);
	
			/* install 3 policies: out, in and forward */
			status = charon->kernel_interface->add_policy(charon->kernel_interface,
					this->me.addr, this->other.addr,
					policy->me.net, policy->other.net,
					policy->me.net_mask, policy->other.net_mask,
					XFRM_POLICY_OUT, policy->upper_proto,
					this->protocol,
					this->reqid);
	
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other.addr, this->me.addr,
					policy->other.net, policy->me.net,
					policy->other.net_mask, policy->me.net_mask,
					XFRM_POLICY_IN, policy->upper_proto,
					this->protocol,
					this->reqid);
	
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other.addr, this->me.addr,
					policy->other.net, policy->me.net,
					policy->other.net_mask, policy->me.net_mask,
					XFRM_POLICY_FWD, policy->upper_proto,
					this->protocol,
					this->reqid);
			
			if (status != SUCCESS)
			{
				my_iter->destroy(my_iter);
				other_iter->destroy(other_iter);
				policy->me.net->destroy(policy->me.net);
				policy->other.net->destroy(policy->other.net);
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
	logger->log(logger, CONTROL|LEVEL1, "  \"%s\":   protected with %s (0x%x/0x%x), reqid %d:",
				name,
				this->protocol == PROTO_ESP ? "ESP" : "AH",
				htonl(this->me.spi), htonl(this->other.spi),
				this->reqid);
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
		logger->log(logger, CONTROL, "  \"%s\":     %s/%d==%s==%s/%d",
					name,
					policy->me.net->get_address(policy->me.net), policy->me.net_mask,
					proto_name,
					policy->other.net->get_address(policy->other.net), policy->other.net_mask);
	}
	iterator->destroy(iterator);
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	/* delete all policies in the kernel */
	sa_policy_t *policy;
	while (this->policies->remove_last(this->policies, (void**)&policy) == SUCCESS)
	{
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->me.addr, this->other.addr,
											 policy->me.net, policy->other.net,
											 policy->me.net_mask, policy->other.net_mask,
											 XFRM_POLICY_OUT, policy->upper_proto);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->other.addr, this->me.addr,
											 policy->other.net, policy->me.net,
											 policy->other.net_mask, policy->me.net_mask,
											 XFRM_POLICY_IN, policy->upper_proto);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 this->other.addr, this->me.addr,
											 policy->other.net, policy->me.net,
											 policy->other.net_mask, policy->me.net_mask,
											 XFRM_POLICY_FWD, policy->upper_proto);
		
		policy->me.net->destroy(policy->me.net);
		policy->other.net->destroy(policy->other.net);
		free(policy);
	}
	this->policies->destroy(this->policies);
	
	/* delete SAs in the kernel, if they are set up */
	if (this->protocol != PROTO_NONE)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->other.addr, this->me.spi, this->protocol);
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me.addr, this->other.spi, this->protocol);
	}
	free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(host_t *me, host_t* other, u_int32_t soft_lifetime, u_int32_t hard_lifetime)
{
	static u_int32_t reqid = 2000000000;
	private_child_sa_t *this = malloc_thing(private_child_sa_t);

	/* public functions */
	this->public.get_reqid = (u_int32_t(*)(child_sa_t*))get_reqid;
	this->public.get_spi = (u_int32_t(*)(child_sa_t*, bool))get_spi;
	this->public.get_protocol = (protocol_id_t(*)(child_sa_t*))get_protocol;
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))update;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*))add_policies;
	this->public.log_status = (void (*)(child_sa_t*, logger_t*, char*))log_status;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->logger = logger_manager->get_logger(logger_manager, CHILD_SA);
	this->me.addr = me;
	this->other.addr = other;
	this->me.spi = 0;
	this->other.spi = 0;
	this->soft_lifetime = soft_lifetime;
	this->hard_lifetime = hard_lifetime;
	this->reqid = ++reqid;
	this->policies = linked_list_create();
	this->protocol = PROTO_NONE;
	
	return (&this->public);
}
