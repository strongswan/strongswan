/**
 * @file child_sa.c
 *
 * @brief Implementation of child_sa_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
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

#include "child_sa.h"

#include <daemon.h>


/**
 * String mappings for child_sa_state_t.
 */
mapping_t child_sa_state_m[] = {
	{CHILD_CREATED, "CREATED"},
	{CHILD_INSTALLED, "INSTALLED"},
	{CHILD_REKEYING, "REKEYING"},
	{CHILD_DELETING, "DELETING"},
	{MAPPING_END, NULL}
};

typedef struct sa_policy_t sa_policy_t;

/**
 * Struct used to store information for a policy. This
 * is needed since we must provide all this information
 * for deleting a policy...
 */
struct sa_policy_t {
	/**
	 * Traffic selector for us
	 */
	traffic_selector_t *my_ts;
	
	/**
	 * Traffic selector for other
	 */
	traffic_selector_t *other_ts;
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
	 * List containing sa_policy_t objects 
	 */
	linked_list_t *policies;
	
	/**
	 * Seperate list for local traffic selectors
	 */
	linked_list_t *my_ts;
	
	/**
	 * Seperate list for remote traffic selectors
	 */
	linked_list_t *other_ts;
	
	/**
	 * reqid used for this child_sa
	 */
	u_int32_t reqid;
	
	/**
	 * encryption algorithm used for this SA
	 */
	algorithm_t encryption;
	
	/**
	 * integrity protection algorithm used for this SA
	 */
	algorithm_t integrity;
	
	/**
	 * time, on which SA was installed
	 */
	time_t install_time;
	
	/**
	 * Lifetime before rekeying
	 */
	u_int32_t soft_lifetime;
	
	/**
	 * Lifetime before delete
	 */
	u_int32_t hard_lifetime;
	
	/**
	 * state of the CHILD_SA
	 */
	child_sa_state_t state;
	
	/**
	 * transaction which is rekeying this CHILD_SA
	 */
	void *rekeying_transaction;

	/**
	 * Specifies if NAT traversal is used
	 */
	bool use_natt;
	
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
 * Implements child_sa_t.get_state
 */
static child_sa_state_t get_state(private_child_sa_t *this)
{
	return this->state;
}

/**
 * Implements child_sa_t.set_state
 */
static void set_state(private_child_sa_t *this, child_sa_state_t state)
{
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
						 this->other.addr, this->me.addr,
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
						 this->other.addr, this->me.addr,
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
	while(iterator->has_next(iterator))
	{
		iterator->current(iterator, (void**)&proposal);
		if (alloc_proposal(this, proposal) != SUCCESS)
		{
			iterator->destroy(iterator);
			return FAILED;
		}
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
	natt_conf_t *natt;
	status_t status;
	
	this->protocol = proposal->get_protocol(proposal);
	
	/* now we have to decide which spi to use. Use self allocated, if "mine",
	 * or the one in the proposal, if not "mine" (others). Additionally,
	 * source and dest host switch depending on the role */
	if (mine)
	{
		/* if we have allocated SPIs for AH and ESP, we must delete the unused
		 * one. */
		if (this->protocol == PROTO_ESP)
		{
			this->me.spi = this->alloc_esp_spi;
			if (this->alloc_ah_spi)
			{
				charon->kernel_interface->del_sa(charon->kernel_interface, this->me.addr, 
						this->alloc_ah_spi, PROTO_AH);
			}
		}
		else
		{
			this->me.spi = this->alloc_ah_spi;
			if (this->alloc_esp_spi)
			{
				charon->kernel_interface->del_sa(charon->kernel_interface, this->me.addr, 
						this->alloc_esp_spi, PROTO_ESP);
			}
		}
		spi = this->me.spi;
		dst = this->me.addr;
		src = this->other.addr;
	}
	else
	{
		this->other.spi = proposal->get_spi(proposal);
		spi = this->other.spi;
		src = this->me.addr;
		dst = this->other.addr;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL1, "adding %s %s SA",
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
	
	/* setup nat-t */
	if (this->use_natt)
	{
		natt = alloca(sizeof(natt_conf_t));
		natt->sport = src->get_port(src);
		natt->dport = dst->get_port(dst);
	}
	else
	{
		natt = NULL;
	}
	
	
	/* send SA down to the kernel */
	this->logger->log(this->logger, CONTROL|LEVEL2,
						"  SPI 0x%.8x, src %s dst %s",
						ntohl(spi), src->get_string(src), dst->get_string(dst));
	status = charon->kernel_interface->add_sa(charon->kernel_interface,
											  src, dst,
											  spi, this->protocol,
											  this->reqid,
											  mine ? this->soft_lifetime : 0,
											  this->hard_lifetime,
											  enc_algo, int_algo,
											  prf_plus, natt, mine);
	
	this->encryption = *enc_algo;
	this->integrity = *int_algo;
	this->install_time = time(NULL);
	
	return status;
}

static status_t add(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus)
{
	u_int32_t outbound_spi, inbound_spi;
	
	/* backup outbound spi, as alloc overwrites it */
	outbound_spi = proposal->get_spi(proposal);
	
	/* get SPIs inbound SAs */
	if (alloc_proposal(this, proposal) != SUCCESS)
	{
		return FAILED;
	}
	inbound_spi = proposal->get_spi(proposal);
	
	/* install inbound SAs */
	if (install(this, proposal, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* install outbound SAs, restore spi*/
	proposal->set_spi(proposal, outbound_spi);
	if (install(this, proposal, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	proposal->set_spi(proposal, inbound_spi);
	
	this->state = CHILD_INSTALLED;
	
	return SUCCESS;
}

static status_t update(private_child_sa_t *this, proposal_t *proposal, prf_plus_t *prf_plus)
{
	u_int32_t inbound_spi;
	
	/* backup received spi, as install() overwrites it */
	inbound_spi = proposal->get_spi(proposal);
	
	/* install outbound SAs */
	if (install(this, proposal, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* restore spi */
	proposal->set_spi(proposal, inbound_spi);
	/* install inbound SAs */
	if (install(this, proposal, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	
	this->state = CHILD_INSTALLED;
	
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
			status_t status;
			sa_policy_t *policy;
			
			other_iter->current(other_iter, (void**)&other_ts);
			
			if (my_ts->get_type(my_ts) != other_ts->get_type(other_ts))
			{
				this->logger->log(this->logger, CONTROL|LEVEL1, 
								  "CHILD_SA policy uses two different IP families, ignored");
				continue;
			}
			
			/* only set up policies if protocol matches, or if one is zero (any) */
			if (my_ts->get_protocol(my_ts) != other_ts->get_protocol(other_ts) &&
				my_ts->get_protocol(my_ts) && other_ts->get_protocol(other_ts))
			{
				this->logger->log(this->logger, CONTROL|LEVEL1, 
								  "CHILD_SA policy uses two different protocols, ignored");
				continue;
			}
			
			/* install 3 policies: out, in and forward */
			status = charon->kernel_interface->add_policy(charon->kernel_interface,
					this->me.addr, this->other.addr, my_ts, other_ts, 
					POLICY_OUT, this->protocol, this->reqid, FALSE);
			
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other.addr, this->me.addr, other_ts, my_ts,
					POLICY_IN, this->protocol, this->reqid, FALSE);
			
			status |= charon->kernel_interface->add_policy(charon->kernel_interface,
					this->other.addr, this->me.addr, other_ts, my_ts,
					POLICY_FWD, this->protocol, this->reqid, FALSE);
			
			if (status != SUCCESS)
			{
				my_iter->destroy(my_iter);
				other_iter->destroy(other_iter);
				return status;
			}
			
			/* store policy to delete/update them later */
			policy = malloc_thing(sa_policy_t);
			policy->my_ts = my_ts->clone(my_ts);
			policy->other_ts = other_ts->clone(other_ts);
			this->policies->insert_last(this->policies, (void*)policy);
			/* add to separate list to query them via get_*_traffic_selectors() */
			this->my_ts->insert_last(this->my_ts, (void*)policy->my_ts);
			this->other_ts->insert_last(this->other_ts, (void*)policy->other_ts);
		}
	}
	my_iter->destroy(my_iter);
	other_iter->destroy(other_iter);
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.get_my_traffic_selectors.
 */
static linked_list_t *get_my_traffic_selectors(private_child_sa_t *this)
{
	return this->my_ts;
}

/**
 * Implementation of child_sa_t.get_my_traffic_selectors.
 */
static linked_list_t *get_other_traffic_selectors(private_child_sa_t *this)
{
	return this->other_ts;
}

/**
 * Implementation of child_sa_t.set_rekeying_transaction.
 */
static void set_rekeying_transaction(private_child_sa_t *this, void *transaction)
{
	this->rekeying_transaction = transaction;
}

/**
 * Implementation of child_sa_t.get_rekeying_transaction.
 */
static void* get_rekeying_transaction(private_child_sa_t *this)
{
	return this->rekeying_transaction;
}

/**
 * Implementation of child_sa_t.get_use_time
 */
static status_t get_use_time(private_child_sa_t *this, bool inbound, time_t *use_time)
{
	iterator_t *iterator;
	sa_policy_t *policy;
	status_t status;
	
	*use_time = UNDEFINED_TIME;

	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->iterate(iterator, (void**)&policy))
	{
		if (inbound) 
		{
			time_t in = UNDEFINED_TIME, fwd = UNDEFINED_TIME;
			
			status = charon->kernel_interface->query_policy(
									charon->kernel_interface,
									policy->other_ts, policy->my_ts,
									POLICY_IN, (u_int32_t*)&in);
			status |= charon->kernel_interface->query_policy(
									charon->kernel_interface,
									policy->other_ts, policy->my_ts,
									POLICY_FWD, (u_int32_t*)&fwd);
			*use_time = max(in, fwd);
		}
		else
		{
			status = charon->kernel_interface->query_policy(
									charon->kernel_interface,
									policy->my_ts, policy->other_ts, 
									POLICY_OUT, (u_int32_t*)use_time);
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of child_sa_t.log_status.
 */
static void log_status(private_child_sa_t *this, logger_t *logger, char* name)
{
	iterator_t *iterator;
	char use_in_str[12] = "unused";
	char use_out_str[12] = "unused";
	char rekey_str[12] = "disabled";
	char enc_str[32] = "";
	char int_str[32] = "";
	u_int32_t use_in, use_out, use_fwd, now, rekeying;
	status_t status;
	
	if (logger == NULL)
	{
		logger = this->logger;
	}
	now = (u_int32_t)time(NULL);
	
	/* query SA times */
	status = charon->kernel_interface->query_sa(charon->kernel_interface,
					this->me.addr, this->me.spi, this->protocol, &use_in);
	if (status == SUCCESS && use_in)
	{
		snprintf(use_in_str, sizeof(use_in_str), "%ds", now - use_in);
	}
	status = charon->kernel_interface->query_sa(charon->kernel_interface,
					this->other.addr, this->other.spi, this->protocol, &use_out);
	if (status == SUCCESS && use_out)
	{
		snprintf(use_out_str, sizeof(use_out_str), "%ds", now - use_out);
	}
	
	/* calculate rekey times */
	if (this->soft_lifetime)
	{
		rekeying = this->soft_lifetime - (now - this->install_time);
		snprintf(rekey_str, sizeof(rekey_str), "%ds", (int)rekeying);
	}
	
	/* algorithms used */
	if (this->protocol == PROTO_ESP)
	{
		if (this->encryption.key_size)
		{
			snprintf(enc_str, sizeof(enc_str), "%s-%d,", 
					mapping_find(encryption_algorithm_m, this->encryption.algorithm),
					this->encryption.key_size);
		}
		else
		{
			snprintf(enc_str, sizeof(enc_str), "%s,", 
					mapping_find(encryption_algorithm_m, this->encryption.algorithm));
		}
	}
	if (this->integrity.key_size)
	{
		snprintf(int_str, sizeof(int_str), "%s-%d", 
				 mapping_find(integrity_algorithm_m, this->integrity.algorithm),
				 this->integrity.key_size);
	}
	else
	{
		snprintf(int_str, sizeof(int_str), "%s", 
				 mapping_find(integrity_algorithm_m, this->integrity.algorithm));
	}
	
	logger->log(logger, CONTROL|LEVEL1,
				"  \"%s\":   %s (%s%s), SPIs (in/out): 0x%x/0x%x, reqid: %d",
				name,
				this->protocol == PROTO_ESP ? "ESP" : "AH",
				enc_str, int_str,
				htonl(this->me.spi), htonl(this->other.spi),
				this->reqid);
	logger->log(logger, CONTROL|LEVEL1,
				"  \"%s\":   state: %s, rekeying: %s, key age (in/out): %s/%s",
				name, mapping_find(child_sa_state_m, this->state),
				rekey_str, use_in_str, use_out_str);
	
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->has_next(iterator))
	{
		sa_policy_t *policy;
		char *my_str;
		char *other_str;
		char pol_in_str[12] = "unused";
		char pol_out_str[12] = "unused";
		char pol_fwd_str[12] = "unused";
		
		/* get ts strings */
		iterator->current(iterator, (void**)&policy);
		my_str = policy->my_ts->get_string(policy->my_ts);
		other_str = policy->other_ts->get_string(policy->other_ts);
		
		/* query policy times */
		status = charon->kernel_interface->query_policy(charon->kernel_interface,
						policy->other_ts, policy->my_ts, POLICY_IN, &use_in);
		if (status == SUCCESS && use_in)
		{
			snprintf(pol_in_str, sizeof(pol_in_str), "%ds", now - use_in);
		}
		status = charon->kernel_interface->query_policy(charon->kernel_interface,
						policy->my_ts, policy->other_ts, POLICY_OUT, &use_out);
		if (status == SUCCESS && use_out)
		{
			snprintf(pol_out_str, sizeof(pol_out_str), "%ds", now - use_out);
		}
		status = charon->kernel_interface->query_policy(charon->kernel_interface,
						policy->other_ts, policy->my_ts, POLICY_FWD, &use_fwd);
		if (status == SUCCESS && use_fwd)
		{
			snprintf(pol_fwd_str, sizeof(pol_fwd_str), "%ds", now - use_fwd);
		}
		
		logger->log(logger, CONTROL, 
					"  \"%s\":     %s====%s, last use (in/out/fwd): %s/%s/%s",
					name, my_str, other_str, pol_in_str, pol_out_str, pol_fwd_str);
	}
	iterator->destroy(iterator);
}

/**
 * Update the host adress/port of a SA
 */
static status_t update_sa_hosts(private_child_sa_t *this, host_t *new_me, host_t *new_other, 
								int my_changes, int other_changes, bool mine)
{
	host_t *src, *dst, *new_src, *new_dst;
	int src_changes, dst_changes;
	status_t status;
	u_int32_t spi;
	
	if (mine)
	{
		src = this->other.addr;
		dst = this->me.addr;
		new_src = new_other;
		new_dst = new_me;
		src_changes = other_changes;
		dst_changes = my_changes;
		spi = this->other.spi;
	}
	else
	{
		src = this->me.addr;
		dst = this->other.addr;
		new_src = new_me;
		new_dst = new_other;
		src_changes = my_changes;
		dst_changes = other_changes;
		spi = this->me.spi;
	}
	
	this->logger->log(this->logger, CONTROL|LEVEL1,
					  "updating %s SA 0x%x, from %s:%d..%s:%d to %s:%d..%s:%d",
					  mapping_find(protocol_id_m, this->protocol), ntohl(spi),
					  src->get_string(src), src->get_port(src),
					  dst->get_string(dst), dst->get_port(dst),
					  new_src->get_string(new_src), new_src->get_port(new_src),
					  new_dst->get_string(new_dst), new_dst->get_port(new_dst));
	
	status = charon->kernel_interface->update_sa(charon->kernel_interface,
												 dst, spi, this->protocol, 
												 new_src, new_dst, 
												 src_changes, dst_changes);
	
	if (status != SUCCESS)
	{
		return FAILED;
	}
	return SUCCESS;
}

/**
 * Update the host adress/port of a policy
 */
static status_t update_policy_hosts(private_child_sa_t *this, host_t *new_me, host_t *new_other)
{
	iterator_t *iterator;
	sa_policy_t *policy;
	status_t status;
	
	iterator = this->policies->create_iterator(this->policies, TRUE);
	while (iterator->iterate(iterator, (void**)&policy))
	{
		status = charon->kernel_interface->add_policy(
				charon->kernel_interface,
				new_me, new_other,
				policy->my_ts, policy->other_ts,
				POLICY_OUT, this->protocol, this->reqid, TRUE);
		
		status |= charon->kernel_interface->add_policy(
				charon->kernel_interface,
				new_other, new_me,
				policy->other_ts, policy->my_ts,
				POLICY_IN, this->protocol, this->reqid, TRUE);
		
		status |= charon->kernel_interface->add_policy(
				charon->kernel_interface,
				new_other, new_me,
				policy->other_ts, policy->my_ts,
				POLICY_FWD, this->protocol, this->reqid, TRUE);
		
		if (status != SUCCESS)
		{
			iterator->destroy(iterator);
			return FAILED;
		}
	}
	iterator->destroy(iterator);
	
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.update_hosts.
 */
static status_t update_hosts(private_child_sa_t *this, host_t *new_me, host_t *new_other, 
							 host_diff_t my_changes, host_diff_t other_changes) 
{
	if (!my_changes && !other_changes)
	{
		return SUCCESS;
	}

	/* update our (initator) SAs */
	if (update_sa_hosts(this, new_me, new_other, my_changes, other_changes, TRUE) != SUCCESS)
	{
		return FAILED;
	}

	/* update his (responder) SAs */
	if (update_sa_hosts(this, new_me, new_other, my_changes, other_changes, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* update policies */
	if (my_changes & HOST_DIFF_ADDR || other_changes & HOST_DIFF_ADDR)
	{
		if (update_policy_hosts(this, new_me, new_other) != SUCCESS)
		{
			return FAILED;
		}
	}

	/* update hosts */
	if (my_changes)
	{
		this->me.addr->destroy(this->me.addr);
		this->me.addr = new_me->clone(new_me);
	}

	if (other_changes)
	{
		this->other.addr->destroy(this->other.addr);
		this->other.addr = new_other->clone(new_other);
	}	

	return SUCCESS;
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	sa_policy_t *policy;
	
	/* delete SAs in the kernel, if they are set up */
	if (this->me.spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me.addr, this->me.spi, this->protocol);
	}
	if (this->alloc_esp_spi && this->alloc_esp_spi != this->me.spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me.addr, this->alloc_esp_spi, PROTO_ESP);
	}
	if (this->alloc_ah_spi && this->alloc_ah_spi != this->me.spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->me.addr, this->alloc_ah_spi, PROTO_AH);
	}
	if (this->other.spi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
										 this->other.addr, this->other.spi, this->protocol);
	}
	
	/* delete all policies in the kernel */
	while (this->policies->remove_last(this->policies, (void**)&policy) == SUCCESS)
	{
		/* let rekeyed policies, as they are used by another child_sa */
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 policy->my_ts, policy->other_ts,
											 POLICY_OUT);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 policy->other_ts, policy->my_ts,
											 POLICY_IN);
		
		charon->kernel_interface->del_policy(charon->kernel_interface,
											 policy->other_ts, policy->my_ts,
											 POLICY_FWD);
		policy->my_ts->destroy(policy->my_ts);
		policy->other_ts->destroy(policy->other_ts);
		free(policy);
	}
	this->policies->destroy(this->policies);
	
	this->my_ts->destroy(this->my_ts);
	this->other_ts->destroy(this->other_ts);
	this->me.addr->destroy(this->me.addr);
	this->other.addr->destroy(this->other.addr);
	free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(u_int32_t rekey, host_t *me, host_t* other, 
							 u_int32_t soft_lifetime, u_int32_t hard_lifetime,
							 bool use_natt)
{
	static u_int32_t reqid = REQID_START;
	private_child_sa_t *this = malloc_thing(private_child_sa_t);

	/* public functions */
	this->public.get_reqid = (u_int32_t(*)(child_sa_t*))get_reqid;
	this->public.get_spi = (u_int32_t(*)(child_sa_t*, bool))get_spi;
	this->public.get_protocol = (protocol_id_t(*)(child_sa_t*))get_protocol;
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,prf_plus_t*))update;
	this->public.update_hosts = (status_t (*)(child_sa_t*,host_t*,host_t*,host_diff_t,host_diff_t))update_hosts;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*))add_policies;
	this->public.get_my_traffic_selectors = (linked_list_t*(*)(child_sa_t*))get_my_traffic_selectors;
	this->public.get_other_traffic_selectors = (linked_list_t*(*)(child_sa_t*))get_other_traffic_selectors;
	this->public.get_use_time = (status_t (*)(child_sa_t*,bool,time_t*))get_use_time;
	this->public.set_rekeying_transaction = (void (*)(child_sa_t*,void*))set_rekeying_transaction;
	this->public.get_rekeying_transaction = (void* (*)(child_sa_t*))get_rekeying_transaction;
	this->public.set_state = (void(*)(child_sa_t*,child_sa_state_t))set_state;
	this->public.get_state = (child_sa_state_t(*)(child_sa_t*))get_state;
	this->public.log_status = (void (*)(child_sa_t*, logger_t*, char*))log_status;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->logger = logger_manager->get_logger(logger_manager, CHILD_SA);
	this->me.addr = me->clone(me);
	this->other.addr = other->clone(other);
	this->me.spi = 0;
	this->other.spi = 0;
	this->alloc_ah_spi = 0;
	this->alloc_esp_spi = 0;
	this->use_natt = use_natt;
	this->soft_lifetime = soft_lifetime;
	this->hard_lifetime = hard_lifetime;
	this->state = CHILD_CREATED;
	/* reuse old reqid if we are rekeying an existing CHILD_SA */
	this->reqid = rekey ? rekey : ++reqid;
	this->encryption.algorithm = ENCR_UNDEFINED;
	this->encryption.key_size = 0;
	this->integrity.algorithm = AUTH_UNDEFINED;
	this->encryption.key_size = 0;
	this->policies = linked_list_create();
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	this->protocol = PROTO_NONE;
	this->rekeying_transaction = NULL;
	
	return &this->public;
}
