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
	
	struct {
		/** address of peer */
		host_t *addr;
		/** id of peer */
		identification_t *id;
		/** actual used SPI, 0 if unused */
		u_int32_t spi;
		/** Compression Parameter Index (CPI) used, 0 if unused */
		u_int16_t cpi;
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
	 * Separate list for local traffic selectors
	 */
	linked_list_t *my_ts;
	
	/**
	 * Separate list for remote traffic selectors
	 */
	linked_list_t *other_ts;
	
	/**
	 * reqid used for this child_sa
	 */
	u_int32_t reqid;
	
	/**
	 * encryption algorithm used for this SA
	 */
	u_int16_t enc_alg;
	
	/**
	 * Encryption key data, inbound and outbound
	 */
	chunk_t enc_key[2];
	
	/**
	 * integrity protection algorithm used for this SA
	 */
	u_int16_t int_alg;
	
	/**
	 * integrity key data, inbound and outbound
	 */
	chunk_t int_key[2];
	
	/**
	 * time, on which SA was installed
	 */
	time_t install_time;
	
	/**
	 * absolute time when rekeying is scheduled
	 */
	time_t rekey_time;
	
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
	 * virtual IP assigned to local host
	 */
	host_t *virtual_ip;
	
	/**
	 * config used to create this child
	 */
	child_cfg_t *config;
	
	/**
	 * cached interface name for iptables
	 */
	char *iface;
};

typedef struct keylen_entry_t keylen_entry_t;

/**
 * Implicit key length for an algorithm
 */
struct keylen_entry_t {
	/** IKEv2 algorithm identifier */
	int algo;
	/** key length in bits */
	int len;
};

#define END_OF_LIST -1

/**
 * Keylen for encryption algos
 */
keylen_entry_t keylen_enc[] = {
	{ENCR_DES, 					 64},
	{ENCR_3DES, 				192},
	{END_OF_LIST,				  0}
};

/**
 * Keylen for integrity algos
 */
keylen_entry_t keylen_int[] = {
	{AUTH_HMAC_MD5_96, 			128},
	{AUTH_HMAC_SHA1_96,			160},
	{AUTH_HMAC_SHA2_256_128,	256},
	{AUTH_HMAC_SHA2_384_192,	384},
	{AUTH_HMAC_SHA2_512_256,	512},
	{AUTH_AES_XCBC_96,			128},
	{END_OF_LIST,				  0}
};

/**
 * Lookup key length of an algorithm
 */
static int lookup_keylen(keylen_entry_t *list, int algo)
{
	while (list->algo != END_OF_LIST)
	{
		if (algo == list->algo)
		{
			return list->len;
		}
		list++;
	}
	return 0;
}

/**
 * Implementation of child_sa_t.get_name.
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
	if (inbound)
	{
		return this->me.spi;
	}
	return this->other.spi;
}

/**
 * Implements child_sa_t.get_cpi
 */
u_int16_t get_cpi(private_child_sa_t *this, bool inbound)
{
	if (inbound)
	{
		return this->me.cpi;
	}
	return this->other.cpi;
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
};

/**
 * enumerator function of create_policy_enumerator()
 */
static bool policy_enumerate(policy_enumerator_t *this,
				 traffic_selector_t **my_out, traffic_selector_t **other_out)
{
	traffic_selector_t *my_ts, *other_ts;

	while (this->mine->enumerate(this->mine, &my_ts))
	{
		while (TRUE)
		{
			if (!this->other->enumerate(this->other, &other_ts))
			{	/* end of others list, restart with new of mine */
				this->other->destroy(this->other);
				this->other = this->list->create_enumerator(this->list);
				break;
			}
			if (my_ts->get_type(my_ts) != other_ts->get_type(other_ts))
			{	/* family mismatch */
				continue;
			}
			if (my_ts->get_protocol(my_ts) &&
				other_ts->get_protocol(other_ts) &&
				my_ts->get_protocol(my_ts) != other_ts->get_protocol(other_ts))
			{	/* protocol mismatch */
				continue;
			}
			*my_out = my_ts;
			*other_out = other_ts;
			return TRUE;
		}
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
	
	return &e->public;
}

/**
 * Implementation of child_sa_t.get_stats.
 */
static void get_stats(private_child_sa_t *this, ipsec_mode_t *mode,
					  encryption_algorithm_t *encr_algo,
					  chunk_t *encr_key_in, chunk_t *encr_key_out,
					  integrity_algorithm_t *int_algo,
					  chunk_t *int_key_in, chunk_t *int_key_out,
					  u_int32_t *rekey, u_int32_t *use_in, u_int32_t *use_out,
					  u_int32_t *use_fwd)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	u_int32_t in = 0, out = 0, fwd = 0, time;
	
	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{

		if (charon->kernel_interface->query_policy(charon->kernel_interface,
								other_ts, my_ts, POLICY_IN, &time) == SUCCESS)
		{
			in = max(in, time);
		}
		if (charon->kernel_interface->query_policy(charon->kernel_interface,
								my_ts, other_ts, POLICY_OUT, &time) == SUCCESS)
		{
			out = max(out, time);
		}
		if (charon->kernel_interface->query_policy(charon->kernel_interface,
								other_ts, my_ts, POLICY_FWD, &time) == SUCCESS)
		{
			fwd = max(fwd, time);
		}
	}
	enumerator->destroy(enumerator);

#define SET_PTR_IF(x, y) if (x) { *x = y; }
	SET_PTR_IF(mode, this->mode);
	SET_PTR_IF(encr_algo, this->enc_alg);
	SET_PTR_IF(encr_key_in, this->enc_key[0]);
	SET_PTR_IF(encr_key_out, this->enc_key[1]);
	SET_PTR_IF(int_algo, this->int_alg);
	SET_PTR_IF(int_key_in, this->int_key[0]);
	SET_PTR_IF(int_key_out, this->int_key[1]);
	SET_PTR_IF(rekey, this->rekey_time);
	SET_PTR_IF(use_in, in);
	SET_PTR_IF(use_out, out);
	SET_PTR_IF(use_fwd, fwd);
}

/**
 * Run the up/down script
 */
static void updown(private_child_sa_t *this, bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	char *script;
	
	script = this->config->get_updown(this->config);
	
	if (script == NULL)
	{
		return;
	}
	
	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		char command[1024];
		char *my_client, *other_client, *my_client_mask, *other_client_mask;
		char *pos, *virtual_ip;
		FILE *shell;

		/* get subnet/bits from string */
		asprintf(&my_client, "%R", my_ts);
		pos = strchr(my_client, '/');
		*pos = '\0';
		my_client_mask = pos + 1;
		pos = strchr(my_client_mask, '[');
		if (pos)
		{
			*pos = '\0';
		}
		asprintf(&other_client, "%R", other_ts);
		pos = strchr(other_client, '/');
		*pos = '\0';
		other_client_mask = pos + 1;
		pos = strchr(other_client_mask, '[');
		if (pos)
		{
			*pos = '\0';
		}

		if (this->virtual_ip)
		{
			asprintf(&virtual_ip, "PLUTO_MY_SOURCEIP='%H' ",
		        		 this->virtual_ip);
		}
		else
		{
			asprintf(&virtual_ip, "");
		}

		/* we cache the iface name, as it may not be available when
		 * the SA gets deleted */
		if (up)
		{
			free(this->iface); 
			this->iface = charon->kernel_interface->get_interface(
								charon->kernel_interface, this->me.addr);
		}
		
		/* build the command with all env variables.
		 * TODO: PLUTO_PEER_CA and PLUTO_NEXT_HOP are currently missing
		 */
		snprintf(command, sizeof(command),
				 "2>&1 "
				"PLUTO_VERSION='1.1' "
				"PLUTO_VERB='%s%s%s' "
				"PLUTO_CONNECTION='%s' "
				"PLUTO_INTERFACE='%s' "
				"PLUTO_REQID='%u' "
				"PLUTO_ME='%H' "
				"PLUTO_MY_ID='%D' "
				"PLUTO_MY_CLIENT='%s/%s' "
				"PLUTO_MY_CLIENT_NET='%s' "
				"PLUTO_MY_CLIENT_MASK='%s' "
				"PLUTO_MY_PORT='%u' "
				"PLUTO_MY_PROTOCOL='%u' "
				"PLUTO_PEER='%H' "
				"PLUTO_PEER_ID='%D' "
				"PLUTO_PEER_CLIENT='%s/%s' "
				"PLUTO_PEER_CLIENT_NET='%s' "
				"PLUTO_PEER_CLIENT_MASK='%s' "
				"PLUTO_PEER_PORT='%u' "
				"PLUTO_PEER_PROTOCOL='%u' "
				"%s"
				"%s"
				"%s",
				 up ? "up" : "down",
				 my_ts->is_host(my_ts, this->me.addr) ? "-host" : "-client",
				 this->me.addr->get_family(this->me.addr) == AF_INET ? "" : "-v6",
				 this->config->get_name(this->config),
				 this->iface ? this->iface : "unknown",
				 this->reqid,
				 this->me.addr,
				 this->me.id,
				 my_client, my_client_mask,
				 my_client, my_client_mask,
				 my_ts->get_from_port(my_ts),
				 my_ts->get_protocol(my_ts),
				 this->other.addr,
				 this->other.id,
				 other_client, other_client_mask,
				 other_client, other_client_mask,
				 other_ts->get_from_port(other_ts),
				 other_ts->get_protocol(other_ts),
				 virtual_ip,
				 this->config->get_hostaccess(this->config) ?
				 	"PLUTO_HOST_ACCESS='1' " : "",
				 script);
		free(my_client);
		free(other_client);
		free(virtual_ip);
		
		DBG3(DBG_CHD, "running updown script: %s", command);
		shell = popen(command, "r");

		if (shell == NULL)
		{
			DBG1(DBG_CHD, "could not execute updown script '%s'", script);
			return;
		}
		
		while (TRUE)
		{
			char resp[128];
			
			if (fgets(resp, sizeof(resp), shell) == NULL)
			{
				if (ferror(shell))
				{
					DBG1(DBG_CHD, "error reading output from updown script");
					return;
				}
				else
				{
					break;
				}
			}
			else
			{
				char *e = resp + strlen(resp);
				if (e > resp && e[-1] == '\n')
				{	/* trim trailing '\n' */
					e[-1] = '\0';
				}
				DBG1(DBG_CHD, "updown: %s", resp);
			}
		}
		pclose(shell);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implements child_sa_t.set_state
 */
static void set_state(private_child_sa_t *this, child_sa_state_t state)
{
	if (state == CHILD_INSTALLED)
	{
		updown(this, TRUE);
	}
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

static status_t install(private_child_sa_t *this, proposal_t *proposal,
						ipsec_mode_t mode, prf_plus_t *prf_plus, bool mine)
{
	u_int32_t spi, cpi, soft, hard;
	host_t *src, *dst;
	status_t status;
	int add_keymat;
	u_int16_t enc_size, int_size;
	
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
				charon->kernel_interface->del_sa(charon->kernel_interface,
								this->me.addr, this->alloc_ah_spi, PROTO_AH);
			}
		}
		else
		{
			this->me.spi = this->alloc_ah_spi;
			if (this->alloc_esp_spi)
			{
				charon->kernel_interface->del_sa(charon->kernel_interface,
								this->me.addr, this->alloc_esp_spi, PROTO_ESP);
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
	
	DBG2(DBG_CHD, "adding %s %N SA", mine ? "inbound" : "outbound",
		 protocol_id_names, this->protocol);
	
	/* select encryption algo, derive key */
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM,
								&this->enc_alg, &enc_size))
	{
		DBG2(DBG_CHD, "  using %N for encryption", 
			 encryption_algorithm_names, this->enc_alg);
	}
	if (this->enc_alg != ENCR_UNDEFINED)
	{
		if (!enc_size)
		{
			enc_size = lookup_keylen(keylen_enc, this->enc_alg);
		}
		if (!enc_size)
		{
			DBG1(DBG_CHD, "no keylenth defined for %N",
				 encryption_algorithm_names, this->enc_alg);
			return FAILED;
		}
	 	/* CCM/GCM needs additional keymat */
		switch (this->enc_alg)
		{
			case ENCR_AES_CCM_ICV8:
			case ENCR_AES_CCM_ICV12:
			case ENCR_AES_CCM_ICV16:
				enc_size += 24;
				break;		
			case ENCR_AES_GCM_ICV8:
			case ENCR_AES_GCM_ICV12:
			case ENCR_AES_GCM_ICV16:
				enc_size += 32;
				break;
			default:
				add_keymat = 0;
				break;
		}
		prf_plus->allocate_bytes(prf_plus, enc_size / 8, &this->enc_key[!!mine]);
	}
	
	/* select integrity algo, derive key */
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM,
								&this->int_alg, &int_size))
	{
		DBG2(DBG_CHD, "  using %N for integrity",
			 integrity_algorithm_names, this->int_alg);
	}
	if (this->int_alg != AUTH_UNDEFINED)
	{
		if (!int_size)
		{
			int_size = lookup_keylen(keylen_int, this->int_alg);
		}
		if (!enc_size)
		{
			DBG1(DBG_CHD, "no keylenth defined for %N",
				 integrity_algorithm_names, this->int_alg);
			return FAILED;
		}
		prf_plus->allocate_bytes(prf_plus, int_size / 8, &this->int_key[!!mine]);
	}
	
	/* send SA down to the kernel */
	DBG2(DBG_CHD, "  SPI 0x%.8x, src %H dst %H", ntohl(spi), src, dst);
	
	if (this->ipcomp != IPCOMP_NONE)
	{
		/* we install an additional IPComp SA */
		cpi = htonl(ntohs(mine ? this->me.cpi : this->other.cpi));
		charon->kernel_interface->add_sa(charon->kernel_interface,
				src, dst, cpi, IPPROTO_COMP, this->reqid, 0, 0,
				ENCR_UNDEFINED, chunk_empty, AUTH_UNDEFINED, chunk_empty,
				mode, this->ipcomp, FALSE, mine);
	}
	
	soft = this->config->get_lifetime(this->config, TRUE);
	hard = this->config->get_lifetime(this->config, FALSE);
	status = charon->kernel_interface->add_sa(charon->kernel_interface, src, dst,
				spi, this->protocol, this->reqid, mine ? soft : 0, hard, 
				this->enc_alg, this->enc_key[!!mine],
				this->int_alg, this->int_key[!!mine],
				mode, IPCOMP_NONE, this->encap, mine);
	
	this->install_time = time(NULL);
	this->rekey_time = this->install_time + soft;
	return status;
}

static status_t add(private_child_sa_t *this, proposal_t *proposal, 
					ipsec_mode_t mode, prf_plus_t *prf_plus)
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
	if (install(this, proposal, mode, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* install outbound SAs, restore spi*/
	proposal->set_spi(proposal, outbound_spi);
	if (install(this, proposal, mode, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	proposal->set_spi(proposal, inbound_spi);
	
	return SUCCESS;
}

static status_t update(private_child_sa_t *this, proposal_t *proposal,
					   ipsec_mode_t mode, prf_plus_t *prf_plus)
{
	u_int32_t inbound_spi;
	
	/* backup received spi, as install() overwrites it */
	inbound_spi = proposal->get_spi(proposal);
	
	/* install outbound SAs */
	if (install(this, proposal, mode, prf_plus, FALSE) != SUCCESS)
	{
		return FAILED;
	}
	
	/* restore spi */
	proposal->set_spi(proposal, inbound_spi);
	/* install inbound SAs */
	if (install(this, proposal, mode, prf_plus, TRUE) != SUCCESS)
	{
		return FAILED;
	}
	
	return SUCCESS;
}

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
				this->me.addr, this->other.addr, my_ts, other_ts, POLICY_OUT,
				this->protocol, this->reqid, high_prio, mode, this->ipcomp);
		
		status |= charon->kernel_interface->add_policy(charon->kernel_interface,
				this->other.addr, this->me.addr, other_ts, my_ts, POLICY_IN,
				this->protocol, this->reqid, high_prio, mode, this->ipcomp);
		
		status |= charon->kernel_interface->add_policy(charon->kernel_interface,
				this->other.addr, this->me.addr, other_ts, my_ts, POLICY_FWD,
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
	if (local)
	{
		return this->my_ts;
	}
	return this->other_ts;
}

/**
 * Implementation of child_sa_t.get_use_time
 */
static status_t get_use_time(private_child_sa_t *this,
							 bool inbound, time_t *use_time)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	status_t status = FAILED;
	
	*use_time = UNDEFINED_TIME;

	enumerator = create_policy_enumerator(this);
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
	{
		if (inbound) 
		{
			time_t in = UNDEFINED_TIME, fwd = UNDEFINED_TIME;
			
			status = charon->kernel_interface->query_policy(
									charon->kernel_interface, other_ts, my_ts,
									POLICY_IN, (u_int32_t*)&in);
			status |= charon->kernel_interface->query_policy(
									charon->kernel_interface, other_ts, my_ts,
									POLICY_FWD, (u_int32_t*)&fwd);
			*use_time = max(in, fwd);
		}
		else
		{
			status = charon->kernel_interface->query_policy(
									charon->kernel_interface, my_ts, other_ts,
									POLICY_OUT, (u_int32_t*)use_time);
		}
	}
	enumerator->destroy(enumerator);
	return status;
}

/**
 * Implementation of child_sa_t.update_hosts.
 */
static status_t update_hosts(private_child_sa_t *this, 
							 host_t *me, host_t *other, bool encap) 
{
	/* anything changed at all? */
	if (me->equals(me, this->me.addr) && 
		other->equals(other, this->other.addr) && this->encap == encap)
	{
		return SUCCESS;
	}
	/* run updown script to remove iptables rules */
	updown(this, FALSE);
	
	this->encap = encap;
	
	if (this->ipcomp != IPCOMP_NONE)
	{
		/* update our (initator) IPComp SA */
		charon->kernel_interface->update_sa(charon->kernel_interface, htonl(ntohs(this->me.cpi)),
				IPPROTO_COMP, this->other.addr, this->me.addr, other, me, FALSE);
		/* update his (responder) IPComp SA */
		charon->kernel_interface->update_sa(charon->kernel_interface, htonl(ntohs(this->other.cpi)), 
				IPPROTO_COMP, this->me.addr, this->other.addr, me, other, FALSE);
	}
	
	/* update our (initator) SA */
	charon->kernel_interface->update_sa(charon->kernel_interface, this->me.spi,
			this->protocol, this->other.addr, this->me.addr, other, me, encap);
	/* update his (responder) SA */
	charon->kernel_interface->update_sa(charon->kernel_interface, this->other.spi, 
			this->protocol, this->me.addr, this->other.addr, me, other, encap);
	
	/* update policies */
	if (!me->ip_equals(me, this->me.addr) ||
		!other->ip_equals(other, this->other.addr))
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
			if (!me->ip_equals(me, this->me.addr) &&
				my_ts->is_host(my_ts, this->me.addr))
			{
				my_ts->set_address(my_ts, me);
			}
			if (!other->ip_equals(other, this->other.addr) &&
				other_ts->is_host(other_ts, this->other.addr))
			{
				other_ts->set_address(other_ts, other);
			}
			
			/* we reinstall the virtual IP to handle interface roaming
			 * correctly */
			if (this->virtual_ip)
			{
				charon->kernel_interface->del_ip(charon->kernel_interface,
												 this->virtual_ip);
				charon->kernel_interface->add_ip(charon->kernel_interface,
												 this->virtual_ip, me);
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
	if (!me->equals(me, this->me.addr))
	{
		this->me.addr->destroy(this->me.addr);
		this->me.addr = me->clone(me);
	}
	if (!other->equals(other, this->other.addr))
	{
		this->other.addr->destroy(this->other.addr);
		this->other.addr = other->clone(other);
	}
	
	/* install new iptables rules */
	updown(this, TRUE);
	
	return SUCCESS;
}

/**
 * Implementation of child_sa_t.set_virtual_ip.
 */
static void set_virtual_ip(private_child_sa_t *this, host_t *ip)
{
	this->virtual_ip = ip->clone(ip);
}

/**
 * Implementation of child_sa_t.activate_ipcomp.
 */
static void activate_ipcomp(private_child_sa_t *this, ipcomp_transform_t ipcomp,
		u_int16_t other_cpi)
{
	this->ipcomp = ipcomp;
	this->other.cpi = other_cpi;
}

/**
 * Implementation of child_sa_t.allocate_cpi.
 */
static u_int16_t allocate_cpi(private_child_sa_t *this)
{
	if (!this->cpi_allocated)
	{
		charon->kernel_interface->get_cpi(charon->kernel_interface,
			this->other.addr, this->me.addr, this->reqid, &this->me.cpi);
		this->cpi_allocated = TRUE;
	}
	return this->me.cpi;
}

/**
 * Implementation of child_sa_t.destroy.
 */
static void destroy(private_child_sa_t *this)
{
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;
	
	if (this->state == CHILD_DELETING || this->state == CHILD_INSTALLED)
	{
		updown(this, FALSE);
	}
	
	set_state(this, CHILD_DESTROYING);
	
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
	if (this->me.cpi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->me.addr, htonl(ntohs(this->me.cpi)), IPPROTO_COMP);
	}
	if (this->other.cpi)
	{
		charon->kernel_interface->del_sa(charon->kernel_interface,
					this->other.addr, htonl(ntohs(this->other.cpi)), IPPROTO_COMP);
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
	
	chunk_clear(&this->enc_key[0]);
	chunk_clear(&this->enc_key[1]);
	chunk_clear(&this->int_key[0]);
	chunk_clear(&this->int_key[1]);
	this->my_ts->destroy_offset(this->my_ts, offsetof(traffic_selector_t, destroy));
	this->other_ts->destroy_offset(this->other_ts, offsetof(traffic_selector_t, destroy));
	this->me.addr->destroy(this->me.addr);
	this->other.addr->destroy(this->other.addr);
	this->me.id->destroy(this->me.id);
	this->other.id->destroy(this->other.id);
	this->config->destroy(this->config);
	free(this->iface);
	DESTROY_IF(this->virtual_ip);
	free(this);
}

/*
 * Described in header.
 */
child_sa_t * child_sa_create(host_t *me, host_t* other,
							 identification_t *my_id, identification_t *other_id,
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
	this->public.get_stats = (void(*)(child_sa_t*, ipsec_mode_t*,encryption_algorithm_t*,chunk_t*,chunk_t*,integrity_algorithm_t*,chunk_t*,chunk_t*,u_int32_t*,u_int32_t*,u_int32_t*,u_int32_t*))get_stats;
	this->public.alloc = (status_t(*)(child_sa_t*,linked_list_t*))alloc;
	this->public.add = (status_t(*)(child_sa_t*,proposal_t*,ipsec_mode_t,prf_plus_t*))add;
	this->public.update = (status_t(*)(child_sa_t*,proposal_t*,ipsec_mode_t,prf_plus_t*))update;
	this->public.update_hosts = (status_t (*)(child_sa_t*,host_t*,host_t*,bool))update_hosts;
	this->public.add_policies = (status_t (*)(child_sa_t*, linked_list_t*,linked_list_t*,ipsec_mode_t,protocol_id_t))add_policies;
	this->public.get_traffic_selectors = (linked_list_t*(*)(child_sa_t*,bool))get_traffic_selectors;
	this->public.create_policy_enumerator = (enumerator_t*(*)(child_sa_t*))create_policy_enumerator;
	this->public.get_use_time = (status_t (*)(child_sa_t*,bool,time_t*))get_use_time;
	this->public.set_state = (void(*)(child_sa_t*,child_sa_state_t))set_state;
	this->public.get_state = (child_sa_state_t(*)(child_sa_t*))get_state;
	this->public.get_config = (child_cfg_t*(*)(child_sa_t*))get_config;
	this->public.activate_ipcomp = (void(*)(child_sa_t*,ipcomp_transform_t,u_int16_t))activate_ipcomp;
	this->public.allocate_cpi = (u_int16_t(*)(child_sa_t*))allocate_cpi;
	this->public.set_virtual_ip = (void(*)(child_sa_t*,host_t*))set_virtual_ip;
	this->public.destroy = (void(*)(child_sa_t*))destroy;

	/* private data */
	this->me.addr = me->clone(me);
	this->other.addr = other->clone(other);
	this->me.id = my_id->clone(my_id);
	this->other.id = other_id->clone(other_id);
	this->me.spi = 0;
	this->me.cpi = 0;
	this->other.spi = 0;
	this->other.cpi = 0;
	this->alloc_ah_spi = 0;
	this->alloc_esp_spi = 0;
	this->encap = encap;
	this->cpi_allocated = FALSE;
	this->ipcomp = IPCOMP_NONE;
	this->state = CHILD_CREATED;
	/* reuse old reqid if we are rekeying an existing CHILD_SA */
	this->reqid = rekey ? rekey : ++reqid;
	this->enc_alg = ENCR_UNDEFINED;
	this->enc_key[0] = this->enc_key[1] = chunk_empty;
	this->int_alg = AUTH_UNDEFINED;
	this->int_key[0] = this->int_key[1] = chunk_empty;
	this->my_ts = linked_list_create();
	this->other_ts = linked_list_create();
	this->protocol = PROTO_NONE;
	this->mode = MODE_TUNNEL;
	this->virtual_ip = NULL;
	this->iface = NULL;
	this->config = config;
	config->get_ref(config);
	
	return &this->public;
}
