/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
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

#define _GNU_SOURCE
#include "child_sa.h"

#include <stdio.h>
#include <string.h>

#include <daemon.h>

ENUM(child_sa_state_names, CHILD_CREATED, CHILD_DESTROYING,
	"CREATED",
	"ROUTED",
	"INSTALLED",
	"UPDATING",
	"REKEYING",
	"DELETING",
	"DESTROYING",
);

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
	 * address of us
	 */
	host_t *my_addr;
	
	/**
	 * address of remote
	 */
	host_t *other_addr;
	
	/**
	 * our actually used SPI, 0 if unused
	 */
	u_int32_t my_spi;
	
	/**
	 * others used SPI, 0 if unused
	 */
	u_int32_t other_spi;
	
	/**
	 * our Compression Parameter Index (CPI) used, 0 if unused
	 */
	u_int16_t my_cpi;
	
	/**
	 * others Compression Parameter Index (CPI) used, 0 if unused
	 */
	u_int16_t other_cpi;
	
	/**
	 * List for local traffic selectors
	 */
	linked_list_t *my_ts;
	
	/**
	 * List for remote traffic selectors
	 */
	linked_list_t *other_ts;
	
	/**
	 * Allocated SPI for a ESP proposal candidates
	 */
	u_int32_t alloc_esp_spi;
	
	/**
	 * Allocated SPI for a AH proposal candidates
	 */
	u_int32_t alloc_ah_spi;
	
	/**
	 * Protocol used to protect this SA, ESP|AH
	 */
	protocol_id_t protocol;
	
	/**
	 * reqid used for this child_sa
	 */
	u_int32_t reqid;
	
	/**
	 * absolute time when rekeying is scheduled
	 */
	time_t rekey_time;
	
	/**
	 * absolute time when the SA expires
	 */
	time_t expire_time;
	
	/**
	 * state of the CHILD_SA
	 */
	child_sa_state_t state;

	/**
	 * Specifies if UDP encapsulation is enabled (NAT traversal)
	 */
	bool encap;
	
	/**
	 * Specifies the IPComp transform used (IPCOMP_NONE if disabled)
	 */
	ipcomp_transform_t ipcomp;
	
	/**
	 * TRUE if we allocated (or tried to allocate) a CPI
	 */
	bool cpi_allocated;
	
	/**
	 * mode this SA uses, tunnel/transport
	 */
	ipsec_mode_t mode;
	
	/**
 	 * selected proposal
 	 */
 	proposal_t *proposal;
	
	/**
	 * config used to create this child
	 */
	child_cfg_t *config;
};

/**
 * Implementation of child_sa_t.get_namy_
 */
static char *get_name(private_child_sa_t *this)
{
	return this->config->get_name(this->config);
}

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
	return inbound ? this->my_spi : this->other_spi;
}

/**
 * Implements child_sa_t.get_cpi
 */
u_int16_t get_cpi(private_child_sa_t *this, bool inbound)
{
	return inbound ? this->my_cpi : this->other_cpi;
}

/**
 * Implements child_sa_t.get_protocol
 */
protocol_id_t get_protocol(private_child_sa_t *this)
{
	return this->protocol;
}

/**
 * Implementation of child_sa_t.get_mode
 */
static ipsec_mode_t get_mode(private_child_sa_t *this)
{
	return this->mode;
}

/**
 * Implementation of child_sa_t.has_encap
 */
static bool has_encap(private_child_sa_t *this)
{
	return this->encap;
}

/**
 * Implementation of child_sa_t.get_ipcomp
 */
static ipcomp_transform_t get_ipcomp(private_child_sa_t *this)
{
	return this->ipcomp;
}

/**
 * Implements child_sa_t.get_state
 */
static child_sa_state_t get_state(private_child_sa_t *this)
{
	return this->state;
}

/**
 * Implements child_sa_t.get_config
 */
static child_cfg_t* get_config(private_child_sa_t *this)
{
	return this->config;
}

typedef struct policy_enumerator_t policy_enumerator_t;

/**
 * Private policy enumerator
 */
struct policy_enumerator_t {
	/** implements enumerator_t */
	enumerator_t public;
	/** enumerator over own TS */
	enumerator_t *mine;
	/** enumerator over others TS */
	enumerator_t *other;
	/** list of others TS, to recreate enumerator */
	linked_list_t *list;
	/** currently enumerating TS for "me" side */
	traffic_selector_t *ts;
};

/**
 * enumerator function of create_policy_enumerator()
 */
static bool policy_enumerate(policy_enumerator_t *this,
				 traffic_selector_t **my_out, traffic_selector_t **other_out)
{
	traffic_selector_t *other_ts;
	
	while (this->ts || this->mine->enumerate(this->mine, &this->ts))
	{
		if (!this->other->enumerate(this->other, &other_ts))
		{	/* end of others list, restart with new of mine */
			this->other->destroy(this->other);
			this->other = this->list->create_enumerator(this->list);
			this->ts = NULL;
			continue;
		}
		if (this->ts->get_type(this->ts) != other_ts->get_type(other_ts))
		{	/* family mismatch */
			continue;
		}
		if (this->ts->get_protocol(this->ts) &&
			other_ts->get_protocol(other_ts) &&
			this->ts->get_protocol(this->ts) != other_ts->get_protocol(other_ts))
		{	/* protocol mismatch */
			continue;
		}
		*my_out = this->ts;
		*other_out = other_ts;
		return TRUE;
	}
	return FALSE;
}

/**
 * destroy function of create_policy_enumerator()
 */
static void policy_destroy(policy_enumerator_t *this)
{
	this->mine->destroy(this->mine);
	this->other->destroy(this->other);
	free(this);
}

/**
 * Implementation of child_sa_t.create_policy_enumerator
 */
static enumerator_t* create_policy_enumerator(private_child_sa_t *this)
{
	policy_enumerator_t *e = malloc_thing(policy_enumerator_t);
	
	e->public.enumerate = (void*)policy_enumerate;
	e->public.destroy = (void*)policy_destroy;
	e->mine = this->my_ts->create_enumerator(this->my_ts);
	e->other = this->other_ts->create_enumerator(this->other_ts);
	e->list = this->other_ts;
	e->ts = NULL;
	
	return &e->public;
}

/**
 * Implementation of child_sa_t.get_usetime
 */
static u_int32_t get_usetime(private_child_sa_t *this, bool inbound)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	u_int32_t last_use = 0;

	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		u_int32_t in, out, fwd;
		
		if (inbound) 
		{
			if (charon->kernel_interface->query_policy(charon->kernel_interface,
								other_ts, my_ts, POLICY_IN, &in) == SUCCESS)
			{
				last_use = max(last_use, in);
			}
			if (charon->kernel_interface->query_policy(charon->kernel_interface,
								other_ts, my_ts, POLICY_FWD, &fwd) == SUCCESS)
			{
				last_use = max(last_use, fwd);
			}
		}
		else
		{
			if (charon->kernel_interface->query_policy(charon->kernel_interface,
								my_ts, other_ts, POLICY_OUT, &out) == SUCCESS)
			{
				last_use = max(last_use, out);
			}
		}
	}
	enumerator->destroy(enumerator);
	return last_use;
}

/**
 * Implementation of child_sa_t.get_lifetime
 */
static u_int32_t get_lifetime(private_child_sa_t *this, bool hard)
{
	return hard ? this->expire_time : this->rekey_time;
}

/**
 * Implements child_sa_t.set_state
 */
static void set_state(private_child_sa_t *this, child_sa_state_t state)
{
	charon->bus->child_state_change(charon->bus, &this->public, state);
	this->state = state;
}

/**
 * Allocate SPI for a single proposal
 */
static status_t alloc_proposal(private_child_sa_t *this, proposal_t *proposal)
{
	protocol_id_t protocol = proposal->get_protocol(proposal);
		
	if (protocol == PROTO_AH)
	{
		/* get a new spi for AH, if not already done */
		if (this->alloc_ah_spi == 0)
		{
			if (charon->kernel_interface->get_spi(
						 charon->kernel_interface, 
						 this->other_addr, this->my_addr,
						 PROTO_AH, this->reqid,
						 &this->alloc_ah_spi) != SUCCESS)
			{
				return FAILED;
			}
		}
		proposal->set_spi(proposal, this->alloc_ah_spi);
	}
	if (protocol == PROTO_ESP)
	{
		/* get a new spi for ESP, if not already done */
		if (this->alloc_esp_spi == 0)
		{
			if (charon->kernel_interface->get_spi(
						 charon->kernel_interface,
						 this->other_addr, this->my_addr,
						 PROTO_ESP, this->reqid,
						 &this->alloc_esp_spi) != SUCCESS)
			{
				return FAILED;
			}
		}
		proposal->set_spi(proposal, this->alloc_esp_spi);
	}
	return SUCCESS;
}

/**
 * Implements child_sa_t.alloc
 */
static status_t alloc(private_child_sa_t *this, linked_list_t *proposals)
{
	iterator_t *iterator;
	proposal_t *proposal;
	
	/* iterator through proposals to update spis */
	iterator = proposals->create_iterator(proposals, TRUE);
	while(iterator->iterate(iterator, (void**)&proposal))
	{
		if (alloc_proposal(this, proposal) != SUCCESS)
		{
			iterator->destroy(iterator);
			return FAILED;
		}
	}
	iterator->destroy(iterator);
	return SUCCESS;
}

/**
 * Install an SA for one direction
 */
static status_t install(private_child_sa_t *this, proposal_t *proposal,
						ipsec_mode_t mode, chunk_t integ, chunk_t encr, bool in)
{
	u_int16_t enc_alg = ENCR_UNDEFINED, int_alg = AUTH_UNDEFINED, size;
	u_int32_t spi, cpi, soft, hard, now;
	host_t *src, *dst;
	status_t status;
	
	/* now we have to decide which spi to use. Use self allocated, if "in",
	 * or the one in the proposal, if not "in" (others). Additionally,
	 * source and dest host switch depending on the role */
	if (in)
	{
		/* if we have allocated SPIs for AH and ESP, we must delete the unused
		 * one. */
		if (this->protocol == PROTO_ESP)
		{
			this->my_spi = this->alloc_esp_spi;
			if (this->alloc_ah_spi)
			{
				charon->kernel_interface->del_sa(charon->kernel_interface,
								this->my_addr, this->alloc_ah_spi, PROTO_AH);
			}
		}
		else
		{
			this->my_spi = this->alloc_ah_spi;
			if (this->alloc_esp_spi)
			{
				charon->kernel_interface->del_sa(charon->kernel_interface,
								this->my_addr, this->alloc_esp_spi, PROTO_ESP);
			}
		}
		spi = this->my_spi;
		dst = this->my_addr;
		src = this->other_addr;
	}
	else
	{
		this->other_spi = proposal->get_spi(proposal);
		spi = this->other_spi;
		src = this->my_addr;
		dst = this->other_addr;
	}
	
	DBG2(DBG_CHD, "adding %s %N SA", in ? "inbound" : "outbound",
		 protocol_id_names, this->protocol);
	
	/* send SA down to the kernel */
	DBG2(DBG_CHD, "  SPI 0x%.8x, src %H dst %H", ntohl(spi), src, dst);
	
	if (this->ipcomp != IPCOMP_NONE)
	{
		/* we install an additional IPComp SA */
		cpi = htonl(ntohs(in ? this->my_cpi : this->other_cpi));
		charon->kernel_interface->add_sa(charon->kernel_interface,
				src, dst, cpi, IPPROTO_COMP, this->reqid, 0, 0,
				ENCR_UNDEFINED, chunk_empty, AUTH_UNDEFINED, chunk_empty,
				mode, this->ipcomp, FALSE, in);
	}
	
	proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &enc_alg, &size);
	proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &int_alg, &size);
	
	soft = this->config->get_lifetime(this->config, TRUE);
	hard = this->config->get_lifetime(this->config, FALSE);
	status = charon->kernel_interface->add_sa(charon->kernel_interface,
				src, dst, spi, this->protocol, this->reqid,
				in ? soft : 0, hard, enc_alg, encr, int_alg, integ,
				mode, IPCOMP_NONE, this->encap, in);
	
	now = time(NULL);
	this->rekey_time = now + soft;
	this->expire_time = now + hard;
	return status;
}

/**
 * Implementation of child_sa_t.add
 */
static status_t add(private_child_sa_t *this, 
					proposal_t *proposal, ipsec_mode_t mode,
					chunk_t integ_in, chunk_t integ_out,
					chunk_t encr_in, chunk_t encr_out)
{
	this->proposal = proposal->clone(proposal);
	this->protocol = proposal->get_protocol(proposal);
	
	/* get SPIs for inbound SAs, write to proposal */
	if (alloc_proposal(this, proposal) != SUCCESS)
	{
		return FAILED;
	}
	/* install inbound SAs using allocated SPI */
	if (install(this, proposal, mode, integ_in, encr_in, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	/* install outbound SAs using received SPI*/
	if (install(this, this->proposal, mode, integ_out, encr_out, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.update
 */
static status_t update(private_child_sa_t *this,
					   proposal_t *proposal, ipsec_mode_t mode,
					   chunk_t integ_in, chunk_t integ_out,
					   chunk_t encr_in, chunk_t encr_out)
{
	this->proposal = proposal->clone(proposal);
	this->protocol = proposal->get_protocol(proposal);
	
	/* install outbound SAs */
	if (install(this, proposal, mode, integ_out, encr_out, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	/* install inbound SAs */
	if (install(this, proposal, mode, integ_in, encr_in, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.get_proposal
 */
static proposal_t* get_proposal(private_child_sa_t *this)
{
	return this->proposal;
}

/**
 * Implementation of child_sa_t.add_policies
 */
static status_t add_policies(private_child_sa_t *this,
					linked_list_t *my_ts_list, linked_list_t *other_ts_list,
					ipsec_mode_t mode, protocol_id_t proto)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	status_t status = SUCCESS;
	bool high_prio = TRUE;
	
	if (this->state == CHILD_CREATED)
	{	/* use low prio for ROUTED policies */
		high_prio = FALSE;
	}
	if (this->protocol == PROTO_NONE)
	{	/* update if not set yet */
		this->protocol = proto;
	}
	
	/* apply traffic selectors */
	enumerator = my_ts_list->create_enumerator(my_ts_list);
	while (enumerator->enumerate(enumerator, &my_ts))
	{
		this->my_ts->insert_last(this->my_ts, my_ts->clone(my_ts));
	}
	enumerator->destroy(enumerator);
	enumerator = other_ts_list->create_enumerator(other_ts_list);
	while (enumerator->enumerate(enumerator, &other_ts))
	{
		this->other_ts->insert_last(this->other_ts, other_ts->clone(other_ts));
	}
	enumerator->destroy(enumerator);
	
	/* enumerate pairs of traffic selectors */
	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		/* install 3 policies: out, in and forward */
		status |= charon->kernel_interface->add_policy(charon->kernel_interface,
				this->my_addr, this->other_addr, my_ts, other_ts, POLICY_OUT,
				this->protocol, this->reqid, high_prio, mode, this->ipcomp);
		
		status |= charon->kernel_interface->add_policy(charon->kernel_interface,
				this->other_addr, this->my_addr, other_ts, my_ts, POLICY_IN,
				this->protocol, this->reqid, high_prio, mode, this->ipcomp);
		
		status |= charon->kernel_interface->add_policy(charon->kernel_interface,
				this->other_addr, this->my_addr, other_ts, my_ts, POLICY_FWD,
				this->protocol, this->reqid, high_prio, mode, this->ipcomp);
		
		if (status != SUCCESS)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	
	if (status == SUCCESS)
	{
		/* switch to routed state if no SAD entry set up */
		if (this->state == CHILD_CREATED)
		{
			set_state(this, CHILD_ROUTED);
		}
		/* needed to update hosts */
		this->mode = mode;
	}
	return status;
}

/**
 * Implementation of child_sa_t.get_traffic_selectors.
 */
static linked_list_t *get_traffic_selectors(private_child_sa_t *this, bool local)
{
	return local ? this->my_ts : this->other_ts;
}

/**
 * Implementation of child_sa_t.update_hosts.
 */
static status_t update_hosts(private_child_sa_t *this, 
							 host_t *me, host_t *other, host_t *vip, bool encap) 
{
	child_sa_state_t old;
	
	/* anything changed at all? */
	if (me->equals(me, this->my_addr) && 
		other->equals(other, this->other_addr) && this->encap == encap)
	{
		return SUCCESS;
	}
	
	old = this->state;
	set_state(this, CHILD_UPDATING);
	
	this->encap = encap;
	
	if (this->ipcomp != IPCOMP_NONE)
	{
		/* update our (initator) IPComp SA */
		charon->kernel_interface->update_sa(charon->kernel_interface, 
							htonl(ntohs(this->my_cpi)),	IPPROTO_COMP,
							this->other_addr, this->my_addr, other, me, FALSE);
		/* update his (responder) IPComp SA */
		charon->kernel_interface->update_sa(charon->kernel_interface,
							htonl(ntohs(this->other_cpi)), IPPROTO_COMP,
							this->my_addr, this->other_addr, me, other, FALSE);
	}
	
	/* update our (initator) SA */
	charon->kernel_interface->update_sa(charon->kernel_interface, this->my_spi,
			this->protocol, this->other_addr, this->my_addr, other, me, encap);
	/* update his (responder) SA */
	charon->kernel_interface->update_sa(charon->kernel_interface, this->other_spi, 
			this->protocol, this->my_addr, this->other_addr, me, other, encap);
	
	/* update policies */
	if (!me->ip_equals(me, this->my_addr) ||
		!other->ip_equals(other, this->other_addr))
	{
		enumerator_t *enumerator;
		traffic_selector_t *my_ts, *other_ts;
		
		/* always use high priorities, as hosts getting updated are INSTALLED */
		enumerator = create_policy_enumerator(this);
		while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
		{
			/* remove old policies first */
			charon->kernel_interface->del_policy(charon->kernel_interface,
												 my_ts, other_ts, POLICY_OUT);
			charon->kernel_interface->del_policy(charon->kernel_interface,
												 other_ts, my_ts,  POLICY_IN);
			charon->kernel_interface->del_policy(charon->kernel_interface,
												 other_ts, my_ts, POLICY_FWD);
		
			/* check whether we have to update a "dynamic" traffic selector */
			if (!me->ip_equals(me, this->my_addr) &&
				my_ts->is_host(my_ts, this->my_addr))
			{
				my_ts->set_address(my_ts, me);
			}
			if (!other->ip_equals(other, this->other_addr) &&
				other_ts->is_host(other_ts, this->other_addr))
			{
				other_ts->set_address(other_ts, other);
			}
			
			/* we reinstall the virtual IP to handle interface roaming
			 * correctly */
			if (vip)
			{
				charon->kernel_interface->del_ip(charon->kernel_interface, vip);
				charon->kernel_interface->add_ip(charon->kernel_interface, vip, me);
			}
		
			/* reinstall updated policies */
			charon->kernel_interface->add_policy(charon->kernel_interface,
						me, other, my_ts, other_ts, POLICY_OUT, this->protocol,
						this->reqid, TRUE, this->mode, this->ipcomp);
			charon->kernel_interface->add_policy(charon->kernel_interface, 
						other, me, other_ts, my_ts, POLICY_IN, this->protocol,
						this->reqid, TRUE, this->mode, this->ipcomp);
			charon->kernel_interface->add_policy(charon->kernel_interface,
						other, me, other_ts, my_ts, POLICY_FWD, this->protocol,
						this->reqid, TRUE, this->mode, this->ipcomp);
		}
		enumerator->destroy(enumerator);
	}

	/* apply hosts */
	if (!me->equals(me, this->my_addr))
	{
		this->my_addr->destroy(this->my_addr);
		this->my_addr = me->clone(me);
	}
	if (!other->equals(other, this->other_addr))
	{
		this->other_addr->destroy(this->other_addr);
		this->other_addr = other->clone(other);
	}
	
	set_state(this, old);
	
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.activate_ipcomp.
 */
static void activate_ipcomp(private_child_sa_t *this, ipcomp_transform_t ipcomp,
		u_int16_t other_cpi)
{
	this->ipcomp = ipcomp;
	this->other_cpi = other_cpi;
}

/**
 * Implementation of child_sa_t.allocate_cpi.
 */
static u_int16_t allocate_cpi(private_child_sa_t *this)
{
	if (!this->cpi_allocated)
	{
		charon->kernel_interface->get_cpi(charon->kernel_interface,
			this->other_addr, this->my_addr, this->reqid, &this->my_cpi);
		this->cpi_allocated = TRUE;
	}
	return this->my_cpi;
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	
	set_state(this, CHILD_DESTROYING);
	
	/* delete SAs in the kernel, if they are set up */
	if (this->my_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->my_addr, this->my_spi, this->protocol);
	}
	if (this->alloc_esp_spi && this->alloc_esp_spi != this->my_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->my_addr, this->alloc_esp_spi, PROTO_ESP);
	}
	if (this->alloc_ah_spi && this->alloc_ah_spi != this->my_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->my_addr, this->alloc_ah_spi, PROTO_AH);
	}
	if (this->other_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->other_addr, this->other_spi, this->protocol);
	}
	if (this->my_cpi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->my_addr, htonl(ntohs(this->my_cpi)), IPPROTO_COMP);
	}
	if (this->other_cpi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->other_addr, htonl(ntohs(this->other_cpi)), IPPROTO_COMP);
	}
	
	/* delete all policies in the kernel */
	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 my_ts, other_ts, POLICY_OUT);
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 other_ts, my_ts, POLICY_IN);
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 other_ts, my_ts, POLICY_FWD);
	}
	enumerator->destroy(enumerator);
	
	this->my_ts->destroy_offset(this->my_ts, offsetof(traffic_selector_t, destroy));
	this->other_ts->destroy_offset(this->other_ts, offsetof(traffic_selector_t, destroy));
	this->my_addr->destroy(this->my_addr);
	this->other_addr->destroy(this->other_addr);
	DESTROY_IF(this->proposal);
	this->config->destroy(this->config);
	free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(host_t *me, host_t* other,
							 child_cfg_t *config, u_int32_t rekey, bool encap)
{
	static u_int32_t reqid = 0;
	private_child_sa_t *this = malloc_thing(private_child_sa_t);

	/* public functions */
	this->public.get_name = (char*(*)(child_sa_t*))get_name;
	this->public.get_reqid = (u_int32_t(*)(child_sa_t*))get_reqid;
	this->public.get_spi = (u_int32_t(*)(child_sa_t*, bool))get_spi;
	this->public.get_cpi = (u_int16_t(*)(child_sa_t*, bool))get_cpi;
	this->public.get_protocol = (protocol_id_t(*)(child_sa_t*))get_protocol;
	this->public.get_mode = (ipsec_mode_t(*)(child_sa_t*))get_mode;
	this->public.get_ipcomp = (ipcomp_transform_t(*)(child_sa_t*))get_ipcomp;
	this->public.has_encap = (bool(*)(child_sa_t*))has_encap;
	this->public.get_lifetime = (u_int32_t(*)(child_sa_t*, bool))get_lifetime;
	this->public.get_usetime = (u_int32_t(*)(child_sa_t*, bool))get_usetime;
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,ipsec_mode_t,chunk_t,chunk_t,chunk_t,chunk_t))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,ipsec_mode_t,chunk_t,chunk_t,chunk_t,chunk_t))update;
	this->public.get_proposal = (proposal_t*(*)(child_sa_t*))get_proposal;
	this->public.update_hosts = (status_t (*)(child_sa_t*,host_t*,host_t*,host_t*,bool))update_hosts;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*,ipsec_mode_t,protocol_id_t))add_policies;
	this->public.get_traffic_selectors = (linked_list_t*(*)(child_sa_t*,bool))get_traffic_selectors;
	this->public.create_policy_enumerator = (enumerator_t*(*)(child_sa_t*))create_policy_enumerator;
	this->public.set_state = (void(*)(child_sa_t*,child_sa_state_t))set_state;
	this->public.get_state = (child_sa_state_t(*)(child_sa_t*))get_state;
	this->public.get_config = (child_cfg_t*(*)(child_sa_t*))get_config;
	this->public.activate_ipcomp = (void(*)(child_sa_t*,ipcomp_transform_t,u_int16_t))activate_ipcomp;
	this->public.allocate_cpi = (u_int16_t(*)(child_sa_t*))allocate_cpi;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->my_addr = me->clone(me);
	this->other_addr = other->clone(other);
	this->my_spi = 0;
	this->my_cpi = 0;
	this->other_spi = 0;
	this->other_cpi = 0;
	this->alloc_ah_spi = 0;
	this->alloc_esp_spi = 0;
	this->encap = encap;
	this->cpi_allocated = FALSE;
	this->ipcomp = IPCOMP_NONE;
	this->state = CHILD_CREATED;
	/* reuse old reqid if we are rekeying an existing CHILD_SA */
	this->reqid = rekey ? rekey : ++reqid;
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	this->protocol = PROTO_NONE;
	this->mode = MODE_TUNNEL;
	this->proposal = NULL;
	this->config = config;
	config->get_ref(config);
	
	return &this->public;
}

