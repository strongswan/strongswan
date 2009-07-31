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
 */

#define _GNU_SOURCE
#include "child_sa.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <daemon.h>

ENUM(child_sa_state_names, CHILD_CREATED, CHILD_DESTROYING,
	"CREATED",
	"ROUTED",
	"INSTALLING",
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

	/**
	 * time of last use in seconds (inbound)
	 */
	u_int32_t my_usetime;

	/**
	 * time of last use in seconds (outbound)
	 */
	u_int32_t other_usetime;

	/**
	 * last number of inbound bytes
	 */
	u_int64_t my_usebytes;

	/**
	 * last number of outbound bytes
	 */
	u_int64_t other_usebytes;
};

/**
 * Implementation of child_sa_t.get_name
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
 * Implements child_sa_t.get_config
 */
static child_cfg_t* get_config(private_child_sa_t *this)
{
	return this->config;
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
 * Implements child_sa_t.get_state
 */
static child_sa_state_t get_state(private_child_sa_t *this)
{
	return this->state;
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
 * Implementation of child_sa_t.set_protocol
 */
static void set_protocol(private_child_sa_t *this, protocol_id_t protocol)
{
	this->protocol = protocol;
}

/**
 * Implementation of child_sa_t.get_mode
 */
static ipsec_mode_t get_mode(private_child_sa_t *this)
{
	return this->mode;
}

/**
 * Implementation of child_sa_t.set_mode
 */
static void set_mode(private_child_sa_t *this, ipsec_mode_t mode)
{
	this->mode = mode;
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
 * Implementation of child_sa_t.set_ipcomp.
 */
static void set_ipcomp(private_child_sa_t *this, ipcomp_transform_t ipcomp)
{
	this->ipcomp = ipcomp;
}

/**
 * Implementation of child_sa_t.get_proposal
 */
static proposal_t* get_proposal(private_child_sa_t *this)
{
	return this->proposal;
}

/**
 * Implementation of child_sa_t.set_proposal
 */
static void set_proposal(private_child_sa_t *this, proposal_t *proposal)
{
	this->proposal = proposal->clone(proposal);
}

/**
 * Implementation of child_sa_t.get_traffic_selectors.
 */
static linked_list_t *get_traffic_selectors(private_child_sa_t *this, bool local)
{
	return local ? this->my_ts : this->other_ts;
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
static u_int32_t get_usetime(private_child_sa_t *this, bool inbound, bool update)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	u_int32_t last_use = 0;

	if (!update)
	{
		return (inbound) ? this->my_usetime : this->other_usetime;
	}

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
			if (this->mode != MODE_TRANSPORT)
			{
				if (charon->kernel_interface->query_policy(charon->kernel_interface,
								other_ts, my_ts, POLICY_FWD, &fwd) == SUCCESS)
				{
					last_use = max(last_use, fwd);
				}
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
	if (inbound)
	{
		this->my_usetime = last_use;
	}
	else
	{
		this->other_usetime = last_use;
	}
	return last_use;
}

/**
 * Implementation of child_sa_t.get_usebytes
 */
static u_int64_t get_usebytes(private_child_sa_t *this, bool inbound, bool *change)
{
	status_t status;
	u_int64_t bytes;

	*change = FALSE;
	if (inbound) 
	{
		if (this->my_spi)
		{
			status = charon->kernel_interface->query_sa(charon->kernel_interface,
									this->other_addr, this->my_addr,
									this->my_spi, this->protocol, &bytes);
			if (status == SUCCESS && bytes > this->my_usebytes)
			{
				*change = TRUE;
				this->my_usebytes = bytes;
				return bytes;
			}
		}
		return this->my_usebytes;
	}
	else
	{
		if (this->other_spi)
		{
			status = charon->kernel_interface->query_sa(charon->kernel_interface,
									this->my_addr, this->other_addr,
						 			this->other_spi, this->protocol, &bytes);
			if (status == SUCCESS && bytes > this->other_usebytes)
			{
				*change = TRUE;
				this->other_usebytes = bytes;
				return bytes;
			}
		}
		return this->other_usebytes;
	}
}

/**
 * Implementation of child_sa_t.get_lifetime
 */
static u_int32_t get_lifetime(private_child_sa_t *this, bool hard)
{
	return hard ? this->expire_time : this->rekey_time;
}

/**
 * Implementation of child_sa_t.alloc_spi
 */
static u_int32_t alloc_spi(private_child_sa_t *this, protocol_id_t protocol)
{
	if (charon->kernel_interface->get_spi(charon->kernel_interface,
							this->other_addr, this->my_addr, protocol,
							this->reqid, &this->my_spi) == SUCCESS)
	{
		return this->my_spi;
	}
	return 0;
}

/**
 * Implementation of child_sa_t.alloc_cpi
 */
static u_int16_t alloc_cpi(private_child_sa_t *this)
{
	if (charon->kernel_interface->get_cpi(charon->kernel_interface,
					this->other_addr, this->my_addr, this->reqid,
					&this->my_cpi) == SUCCESS)
	{
		return this->my_cpi;
	}
	return 0;
}

/**
 * Implementation of child_sa_t.install
 */
static status_t install(private_child_sa_t *this, chunk_t encr, chunk_t integ,
						u_int32_t spi, u_int16_t cpi, bool inbound)
{
	u_int16_t enc_alg = ENCR_UNDEFINED, int_alg = AUTH_UNDEFINED, size;
	u_int32_t soft, hard, now;
	host_t *src, *dst;
	status_t status;
	bool update = FALSE;
	
	/* now we have to decide which spi to use. Use self allocated, if "in",
	 * or the one in the proposal, if not "in" (others). Additionally,
	 * source and dest host switch depending on the role */
	if (inbound)
	{
		dst = this->my_addr;
		src = this->other_addr;
		if (this->my_spi == spi)
		{	/* alloc_spi has been called, do an SA update */
			update = TRUE;
		}
		this->my_spi = spi;
		this->my_cpi = cpi;
	}
	else
	{
		src = this->my_addr;
		dst = this->other_addr;
		this->other_spi = spi;
		this->other_cpi = cpi;
	}
	
	DBG2(DBG_CHD, "adding %s %N SA", inbound ? "inbound" : "outbound",
		 protocol_id_names, this->protocol);
	
	/* send SA down to the kernel */
	DBG2(DBG_CHD, "  SPI 0x%.8x, src %H dst %H", ntohl(spi), src, dst);
	
	this->proposal->get_algorithm(this->proposal, ENCRYPTION_ALGORITHM,
								  &enc_alg, &size);
	this->proposal->get_algorithm(this->proposal, INTEGRITY_ALGORITHM,
								  &int_alg, &size);
	
	soft = this->config->get_lifetime(this->config, TRUE);
	hard = this->config->get_lifetime(this->config, FALSE);
	
	status = charon->kernel_interface->add_sa(charon->kernel_interface,
				src, dst, spi, this->protocol, this->reqid,
				inbound ? soft : 0, hard, enc_alg, encr, int_alg, integ,
				this->mode, this->ipcomp, cpi, this->encap, update);
	
	now = time(NULL);
	if (soft)
	{
		this->rekey_time = now + soft;
	}
	if (hard)
	{
		this->expire_time = now + hard;
	}
	return status;
}

/**
 * Implementation of child_sa_t.add_policies
 */
static status_t add_policies(private_child_sa_t *this,
					linked_list_t *my_ts_list, linked_list_t *other_ts_list)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	status_t status = SUCCESS;
	bool routed = (this->state == CHILD_CREATED);
	
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
	
	if (this->config->install_policy(this->config))
	{
		/* enumerate pairs of traffic selectors */
		enumerator = create_policy_enumerator(this);
		while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
		{
			/* install 3 policies: out, in and forward */
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->my_addr, this->other_addr, my_ts, other_ts, POLICY_OUT,
					this->other_spi, this->protocol, this->reqid, this->mode,
					this->ipcomp, this->other_cpi, routed);
			
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other_addr, this->my_addr, other_ts, my_ts, POLICY_IN,
					this->my_spi, this->protocol, this->reqid, this->mode,
					this->ipcomp, this->my_cpi, routed);
			if (this->mode != MODE_TRANSPORT)
			{
				status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other_addr, this->my_addr, other_ts, my_ts, POLICY_FWD,
					this->my_spi, this->protocol, this->reqid, this->mode,
					this->ipcomp, this->my_cpi, routed);
			}
			
			if (status != SUCCESS)
			{
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	
	if (status == SUCCESS && this->state == CHILD_CREATED)
	{	/* switch to routed state if no SAD entry set up */
		set_state(this, CHILD_ROUTED);
	}
	return status;
}

/**
 * Implementation of child_sa_t.update.
 */
static status_t update(private_child_sa_t *this,  host_t *me, host_t *other,
					   host_t *vip, bool encap) 
{
	child_sa_state_t old;
	bool transport_proxy_mode;
	
	/* anything changed at all? */
	if (me->equals(me, this->my_addr) && 
		other->equals(other, this->other_addr) && this->encap == encap)
	{
		return SUCCESS;
	}
	
	old = this->state;
	set_state(this, CHILD_UPDATING);
	transport_proxy_mode = this->config->use_proxy_mode(this->config) &&
						   this->mode == MODE_TRANSPORT;
	
	if (!transport_proxy_mode)
	{
		/* update our (initator) SA */
		if (this->my_spi)
		{
			if (charon->kernel_interface->update_sa(charon->kernel_interface,
							this->my_spi, this->protocol,
							this->ipcomp != IPCOMP_NONE ? this->my_cpi : 0,
							this->other_addr, this->my_addr, other, me,
							this->encap, encap) == NOT_SUPPORTED)
			{
				return NOT_SUPPORTED;
			}
		}
		
		/* update his (responder) SA */
		if (this->other_spi)
		{
			if (charon->kernel_interface->update_sa(charon->kernel_interface,
							this->other_spi, this->protocol,
					 		this->ipcomp != IPCOMP_NONE ? this->other_cpi : 0,
							this->my_addr, this->other_addr, me, other,
							this->encap, encap) == NOT_SUPPORTED)
			{
				return NOT_SUPPORTED;
			}
		}
	}
	
	if (this->config->install_policy(this->config))
	{
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
											my_ts, other_ts, POLICY_OUT, FALSE);
				charon->kernel_interface->del_policy(charon->kernel_interface,
											other_ts, my_ts,  POLICY_IN, FALSE);
				if (this->mode != MODE_TRANSPORT)
				{
					charon->kernel_interface->del_policy(charon->kernel_interface,
											other_ts, my_ts, POLICY_FWD, FALSE);
				}
				
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
						me, other, my_ts, other_ts, POLICY_OUT, this->other_spi,
						this->protocol, this->reqid, this->mode, this->ipcomp,
						this->other_cpi, FALSE);
				charon->kernel_interface->add_policy(charon->kernel_interface, 
						other, me, other_ts, my_ts, POLICY_IN, this->my_spi,
						this->protocol, this->reqid, this->mode, this->ipcomp,
						this->my_cpi, FALSE);
				if (this->mode != MODE_TRANSPORT)
				{
					charon->kernel_interface->add_policy(charon->kernel_interface,
						other, me, other_ts, my_ts, POLICY_FWD, this->my_spi,
						this->protocol, this->reqid, this->mode, this->ipcomp,
						this->my_cpi, FALSE);
				}
			}
			enumerator->destroy(enumerator);
		}
	}

	if (!transport_proxy_mode)
	{
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
	}

	this->encap = encap;
	set_state(this, old);

	return SUCCESS;
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	bool unrouted = (this->state == CHILD_ROUTED);
	
	set_state(this, CHILD_DESTROYING);
	
	/* delete SAs in the kernel, if they are set up */
	if (this->my_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->other_addr, this->my_addr, this->my_spi,
					this->protocol, this->my_cpi);
	}
	if (this->other_spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->my_addr, this->other_addr, this->other_spi,
					this->protocol, this->other_cpi);
	}
	
	if (this->config->install_policy(this->config))
	{
		/* delete all policies in the kernel */
		enumerator = create_policy_enumerator(this);
		while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
		{
			charon->kernel_interface->del_policy(charon->kernel_interface,
										my_ts, other_ts, POLICY_OUT, unrouted);
			charon->kernel_interface->del_policy(charon->kernel_interface,
										other_ts, my_ts, POLICY_IN, unrouted);
			if (this->mode != MODE_TRANSPORT)
			{
				charon->kernel_interface->del_policy(charon->kernel_interface,
										other_ts, my_ts, POLICY_FWD, unrouted);
			}
		}
		enumerator->destroy(enumerator);
	}
	
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
	this->public.get_config = (child_cfg_t*(*)(child_sa_t*))get_config;
	this->public.get_state = (child_sa_state_t(*)(child_sa_t*))get_state;
	this->public.set_state = (void(*)(child_sa_t*,child_sa_state_t))set_state;
	this->public.get_spi = (u_int32_t(*)(child_sa_t*, bool))get_spi;
	this->public.get_cpi = (u_int16_t(*)(child_sa_t*, bool))get_cpi;
	this->public.get_protocol = (protocol_id_t(*)(child_sa_t*))get_protocol;
	this->public.set_protocol = (void(*)(child_sa_t*, protocol_id_t protocol))set_protocol;
	this->public.get_mode = (ipsec_mode_t(*)(child_sa_t*))get_mode;
	this->public.set_mode = (void(*)(child_sa_t*, ipsec_mode_t mode))set_mode;
	this->public.get_proposal = (proposal_t*(*)(child_sa_t*))get_proposal;
	this->public.set_proposal = (void(*)(child_sa_t*, proposal_t *proposal))set_proposal;
	this->public.get_lifetime = (u_int32_t(*)(child_sa_t*, bool))get_lifetime;
	this->public.get_usetime = (u_int32_t(*)(child_sa_t*, bool, bool))get_usetime;
	this->public.get_usebytes = (u_int64_t(*)(child_sa_t*, bool, bool*))get_usebytes;
	this->public.has_encap = (bool(*)(child_sa_t*))has_encap;
	this->public.get_ipcomp = (ipcomp_transform_t(*)(child_sa_t*))get_ipcomp;
	this->public.set_ipcomp = (void(*)(child_sa_t*,ipcomp_transform_t))set_ipcomp;
	this->public.alloc_spi = (u_int32_t(*)(child_sa_t*, protocol_id_t protocol))alloc_spi;
	this->public.alloc_cpi = (u_int16_t(*)(child_sa_t*))alloc_cpi;
	this->public.install = (status_t(*)(child_sa_t*, chunk_t encr, chunk_t integ, u_int32_t spi, u_int16_t cpi, bool inbound))install;
	this->public.update = (status_t (*)(child_sa_t*,host_t*,host_t*,host_t*,bool))update;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*))add_policies;
	this->public.get_traffic_selectors = (linked_list_t*(*)(child_sa_t*,bool))get_traffic_selectors;
	this->public.create_policy_enumerator = (enumerator_t*(*)(child_sa_t*))create_policy_enumerator;
	this->public.destroy = (void(*)(child_sa_t*))destroy;
	
	/* private data */
	this->my_addr = me->clone(me);
	this->other_addr = other->clone(other);
	this->my_spi = 0;
	this->other_spi = 0;
	this->my_cpi = 0;
	this->other_cpi = 0;
	this->encap = encap;
	this->ipcomp = IPCOMP_NONE;
	this->state = CHILD_CREATED;
	this->my_usetime = 0;
	this->other_usetime = 0;
	this->my_usebytes = 0;
	this->other_usebytes = 0;
	/* reuse old reqid if we are rekeying an existing CHILD_SA */
	this->reqid = rekey ? rekey : ++reqid;
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	this->protocol = PROTO_NONE;
	this->mode = MODE_TUNNEL;
	this->proposal = NULL;
	this->rekey_time = 0;
	this->expire_time = 0;
	this->config = config;
	config->get_ref(config);
	
	/* MIPv6 proxy transport mode sets SA endpoints to TS hosts */	
	if (config->get_mode(config) == MODE_TRANSPORT &&
	    config->use_proxy_mode(config))
	{
		ts_type_t type;
		int family;
		chunk_t addr;
		host_t *host;
		enumerator_t *enumerator;
		linked_list_t *my_ts_list, *other_ts_list;
		traffic_selector_t *my_ts, *other_ts;
		
		this->mode = MODE_TRANSPORT;
		
		my_ts_list = config->get_traffic_selectors(config, TRUE, NULL, me);
		enumerator = my_ts_list->create_enumerator(my_ts_list);
		if (enumerator->enumerate(enumerator, &my_ts))
		{
			if (my_ts->is_host(my_ts, NULL) &&
			   !my_ts->is_host(my_ts, this->my_addr))
			{
				type = my_ts->get_type(my_ts);
				family = (type == TS_IPV4_ADDR_RANGE) ? AF_INET : AF_INET6;
				addr = my_ts->get_from_address(my_ts);
				host = host_create_from_chunk(family, addr, 0);
				free(addr.ptr);
				DBG1(DBG_CHD, "my address: %H is a transport mode proxy for %H",
							   this->my_addr, host); 
				this->my_addr->destroy(this->my_addr);
				this->my_addr = host;
			}
		}
		enumerator->destroy(enumerator);
		my_ts_list->destroy_offset(my_ts_list, offsetof(traffic_selector_t, destroy));
		
		other_ts_list = config->get_traffic_selectors(config, FALSE, NULL, other);
		enumerator = other_ts_list->create_enumerator(other_ts_list);
		if (enumerator->enumerate(enumerator, &other_ts))
		{
			if (other_ts->is_host(other_ts, NULL) &&
			   !other_ts->is_host(other_ts, this->other_addr))
			{
				type = other_ts->get_type(other_ts);
				family = (type == TS_IPV4_ADDR_RANGE) ? AF_INET : AF_INET6;
				addr = other_ts->get_from_address(other_ts);
				host = host_create_from_chunk(family, addr, 0);
				free(addr.ptr);
				DBG1(DBG_CHD, "other address: %H is a transport mode proxy for %H",
							   this->other_addr, host); 
				this->other_addr->destroy(this->other_addr);
				this->other_addr = host;
			}
		}
		enumerator->destroy(enumerator);
		other_ts_list->destroy_offset(other_ts_list, offsetof(traffic_selector_t, destroy));
	}
	
	return &this->public;
}
