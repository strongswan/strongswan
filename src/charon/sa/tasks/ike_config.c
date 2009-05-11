/*
 * Copyright (C) 2007 Martin Willi
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
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

#include "ike_config.h"

#include <daemon.h>
#include <encoding/payloads/cp_payload.h>

#define DNS_SERVER_MAX		2
#define NBNS_SERVER_MAX		2

typedef struct private_ike_config_t private_ike_config_t;

/**
 * Private members of a ike_config_t task.
 */
struct private_ike_config_t {
	
	/**
	 * Public methods and task_t interface.
	 */
	ike_config_t public;
	
	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;
	
	/**
	 * Are we the initiator?
	 */
	bool initiator;
	
	/**
	 * virtual ip
	 */
	host_t *virtual_ip;
};

/**
 * build INTERNAL_IPV4/6_ADDRESS from virtual ip
 */
static void build_vip(private_ike_config_t *this, host_t *vip, cp_payload_t *cp)
{
	configuration_attribute_t *ca;
	chunk_t chunk, prefix;
	
	ca = configuration_attribute_create();
	
	if (vip->get_family(vip) == AF_INET)
	{
		ca->set_type(ca, INTERNAL_IP4_ADDRESS);
		if (vip->is_anyaddr(vip))
		{
			chunk = chunk_empty;
		}
		else
		{
			chunk = vip->get_address(vip);
		}
	}
	else
	{
		ca->set_type(ca, INTERNAL_IP6_ADDRESS);
		if (vip->is_anyaddr(vip))
		{
			chunk = chunk_empty;
		}
		else
		{
			prefix = chunk_alloca(1);
			*prefix.ptr = 64;
			chunk = vip->get_address(vip);
			chunk = chunk_cata("cc", chunk, prefix);
		}
	}
	ca->set_value(ca, chunk);
	cp->add_configuration_attribute(cp, ca);
}

/**
 * process a single configuration attribute
 */
static void process_attribute(private_ike_config_t *this,
							  configuration_attribute_t *ca)
{
	host_t *ip;
	chunk_t addr;
	int family = AF_INET6;
	
	switch (ca->get_type(ca))
	{
		case INTERNAL_IP4_ADDRESS:
			family = AF_INET;
			/* fall */
		case INTERNAL_IP6_ADDRESS:
		{
			addr = ca->get_value(ca);
			if (addr.len == 0)
			{
				ip = host_create_any(family);
			}
			else
			{
				/* skip prefix byte in IPv6 payload*/
				if (family == AF_INET6)
				{
					addr.len--; 
				}
				ip = host_create_from_chunk(family, addr, 0);
			}
			if (ip)
			{
				DESTROY_IF(this->virtual_ip);
				this->virtual_ip = ip;
			}
			break;
		}
		default:
			if (this->initiator)
			{
				this->ike_sa->add_configuration_attribute(this->ike_sa,
										ca->get_type(ca), ca->get_value(ca));
			}
			else
			{
				/* we do not handle attribute requests other than for VIPs */
			}
	}
}

/**
 * Scan for configuration payloads and attributes
 */
static void process_payloads(private_ike_config_t *this, message_t *message)
{
	enumerator_t *enumerator;
	iterator_t *attributes;
	payload_t *payload;
	
	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == CONFIGURATION)
		{
			cp_payload_t *cp = (cp_payload_t*)payload;
			configuration_attribute_t *ca;
			switch (cp->get_config_type(cp))
			{
				case CFG_REQUEST:
				case CFG_REPLY:
				{
					attributes = cp->create_attribute_iterator(cp);
					while (attributes->iterate(attributes, (void**)&ca))
					{
						process_attribute(this, ca);
					}
					attributes->destroy(attributes);
					break;
				}
				default:
					DBG1(DBG_IKE, "ignoring %N config payload", 
						 config_type_names, cp->get_config_type(cp));
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_config_t *this, message_t *message)
{
	if (message->get_message_id(message) == 1)
	{	/* in first IKE_AUTH only */
		peer_cfg_t *config;
		host_t *vip;
		
		/* reuse virtual IP if we already have one */
		vip = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
		if (!vip)
		{
			config = this->ike_sa->get_peer_cfg(this->ike_sa);
			vip = config->get_virtual_ip(config);
		}
		if (vip)
		{
			configuration_attribute_t *ca;
			cp_payload_t *cp;
			
			cp = cp_payload_create();
			cp->set_config_type(cp, CFG_REQUEST);
			
			build_vip(this, vip, cp);
			
			/* we currently always add a DNS request if we request an IP */
			ca = configuration_attribute_create();
			if (vip->get_family(vip) == AF_INET)
			{
				ca->set_type(ca, INTERNAL_IP4_DNS);
			}
			else
			{
				ca->set_type(ca, INTERNAL_IP6_DNS);
			}
			cp->add_configuration_attribute(cp, ca);
			message->add_payload(message, (payload_t*)cp);
		}
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_config_t *this, message_t *message)
{
	if (message->get_message_id(message) == 1)
	{	/* in first IKE_AUTH only */
		process_payloads(this, message);
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_config_t *this, message_t *message)
{
	if (this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{	/* in last IKE_AUTH exchange */
		peer_cfg_t *config = this->ike_sa->get_peer_cfg(this->ike_sa);
		
		if (config && this->virtual_ip)
		{
			enumerator_t *enumerator;
			configuration_attribute_type_t type;
			configuration_attribute_t *ca;
			chunk_t value;
			cp_payload_t *cp;
			host_t *vip = NULL;
			
			DBG1(DBG_IKE, "peer requested virtual IP %H", this->virtual_ip);
			if (config->get_pool(config))
			{
				vip = charon->attributes->acquire_address(charon->attributes, 
									config->get_pool(config),
									this->ike_sa->get_other_id(this->ike_sa),
									this->virtual_ip);
			}
			if (vip == NULL)
			{
				DBG1(DBG_IKE, "no virtual IP found, sending %N",
					 notify_type_names, INTERNAL_ADDRESS_FAILURE);
				message->add_notify(message, FALSE, INTERNAL_ADDRESS_FAILURE,
									chunk_empty);
				return SUCCESS;
			}
			DBG1(DBG_IKE, "assigning virtual IP %H to peer", vip);
			this->ike_sa->set_virtual_ip(this->ike_sa, FALSE, vip);
			
			cp = cp_payload_create();
			cp->set_config_type(cp, CFG_REQUEST);
			
			build_vip(this, vip, cp);
			vip->destroy(vip);
			
			/* if we add an IP, we also look for other attributes */
			enumerator = charon->attributes->create_attribute_enumerator(
				charon->attributes, this->ike_sa->get_other_id(this->ike_sa));
			while (enumerator->enumerate(enumerator, &type, &value))
			{
				ca = configuration_attribute_create();
				ca->set_type(ca, type);
				ca->set_value(ca, value);
				cp->add_configuration_attribute(cp, ca);
			}
			enumerator->destroy(enumerator);
			
			message->add_payload(message, (payload_t*)cp);
		}
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t process_i(private_ike_config_t *this, message_t *message)
{
	if (this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{	/* in last IKE_AUTH exchange */
		
		process_payloads(this, message);
		
		if (this->virtual_ip)
		{
			this->ike_sa->set_virtual_ip(this->ike_sa, TRUE, this->virtual_ip);
		}
		return SUCCESS;
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.get_type
 */
static task_type_t get_type(private_ike_config_t *this)
{
	return IKE_CONFIG;
}

/**
 * Implementation of task_t.migrate
 */
static void migrate(private_ike_config_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->virtual_ip);
	
	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_config_t *this)
{
	DESTROY_IF(this->virtual_ip);
	free(this);
}

/*
 * Described in header.
 */
ike_config_t *ike_config_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_config_t *this = malloc_thing(private_ike_config_t);
	
	this->public.task.get_type = (task_type_t(*)(task_t*))get_type;
	this->public.task.migrate = (void(*)(task_t*,ike_sa_t*))migrate;
	this->public.task.destroy = (void(*)(task_t*))destroy;
	
	this->initiator = initiator;
	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
	
	if (initiator)
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_i;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_i;
	}
	else
	{
		this->public.task.build = (status_t(*)(task_t*,message_t*))build_r;
		this->public.task.process = (status_t(*)(task_t*,message_t*))process_r;
	}
	
	return &this->public;
}

