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
 *
 * $Id$
 */

#include "ike_config.h"

#include <daemon.h>
#include <encoding/payloads/cp_payload.h>

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
	
	/**
	 * list of DNS servers
	 */
	linked_list_t *dns;
};

/**
 * build configuration payloads and attributes
 */
static void build_payloads(private_ike_config_t *this, message_t *message,
						   config_type_t type)
{
	cp_payload_t *cp;
	configuration_attribute_t *ca;
	chunk_t chunk, prefix;
	
	if (!this->virtual_ip)
	{
		return;
	}

	cp = cp_payload_create();
	cp->set_config_type(cp, type);

	ca = configuration_attribute_create();
	
	if (this->virtual_ip->get_family(this->virtual_ip) == AF_INET)
	{
		ca->set_type(ca, INTERNAL_IP4_ADDRESS);
		if (this->virtual_ip->is_anyaddr(this->virtual_ip))
		{
			chunk = chunk_empty;
		}
		else
		{
			chunk = this->virtual_ip->get_address(this->virtual_ip);
		}
	}
	else
	{
		ca->set_type(ca, INTERNAL_IP6_ADDRESS);
		if (this->virtual_ip->is_anyaddr(this->virtual_ip))
		{
			chunk = chunk_empty;
		}
		else
		{
			prefix = chunk_alloca(1);
			*prefix.ptr = 64;
			chunk = this->virtual_ip->get_address(this->virtual_ip);
			chunk = chunk_cata("cc", chunk, prefix);
		}
	}
	ca->set_value(ca, chunk);
	cp->add_configuration_attribute(cp, ca);
	
	/* we currently always add a DNS request if we request an IP */
	if (this->initiator)
	{
		ca = configuration_attribute_create();
		if (this->virtual_ip->get_family(this->virtual_ip) == AF_INET)
		{
			ca->set_type(ca, INTERNAL_IP4_DNS);
		}
		else
		{
			ca->set_type(ca, INTERNAL_IP6_DNS);
		}
		cp->add_configuration_attribute(cp, ca);
	}
	else
	{
		host_t *ip;
		iterator_t *iterator = this->dns->create_iterator(this->dns, TRUE);
		while (iterator->iterate(iterator, (void**)&ip))
		{
			ca = configuration_attribute_create();
			if (ip->get_family(ip) == AF_INET)
			{
				ca->set_type(ca, INTERNAL_IP4_DNS);
			}
			else
			{
				ca->set_type(ca, INTERNAL_IP6_DNS);
			}
			chunk = ip->get_address(ip);
			ca->set_value(ca, chunk);
			cp->add_configuration_attribute(cp, ca);
		}
		iterator->destroy(iterator);
	}
	message->add_payload(message, (payload_t*)cp);
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
			if (ip && !this->virtual_ip)
			{
				this->virtual_ip = ip;
			}
			break;
		}
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			/* fall */
		case INTERNAL_IP6_DNS:
		{
			addr = ca->get_value(ca);
			if (addr.len == 0)
			{
				ip = host_create_any(family);
			}
			else
			{
				ip = host_create_from_chunk(family, addr, 0);
			}
			if (ip)
			{
				this->dns->insert_last(this->dns, ip);
			}
			break;
		}
		case INTERNAL_IP4_NBNS:
		case INTERNAL_IP6_NBNS:
			/* TODO */
		default:
			DBG1(DBG_IKE, "ignoring %N config attribute", 
	 			 configuration_attribute_type_names,
	 			 ca->get_type(ca));
			break;
	}
}

/**
 * Scan for configuration payloads and attributes
 */
static void process_payloads(private_ike_config_t *this, message_t *message)
{
	iterator_t *iterator, *attributes;
	payload_t *payload;
	
	iterator = message->get_payload_iterator(message);
	while (iterator->iterate(iterator, (void**)&payload))
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
	iterator->destroy(iterator);
}

/**
 * Implementation of task_t.process for initiator
 */
static status_t build_i(private_ike_config_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		message->get_payload(message, ID_INITIATOR))
	{
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
			this->virtual_ip = vip->clone(vip);
		}
		
		build_payloads(this, message, CFG_REQUEST);
	}
	
	return NEED_MORE;
}

/**
 * Implementation of task_t.process for responder
 */
static status_t process_r(private_ike_config_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		message->get_payload(message, ID_INITIATOR))
	{
		process_payloads(this, message);
	}
	return NEED_MORE;
}

/**
 * Implementation of task_t.build for responder
 */
static status_t build_r(private_ike_config_t *this, message_t *message)
{
	if (message->get_exchange_type(message) == IKE_AUTH &&
		message->get_payload(message, EXTENSIBLE_AUTHENTICATION) == NULL)
	{
		peer_cfg_t *config = this->ike_sa->get_peer_cfg(this->ike_sa);
		
		if (config && this->virtual_ip)
		{
			host_t *ip;
			
			DBG1(DBG_IKE, "peer requested virtual IP %H", this->virtual_ip);
			ip = charon->attributes->acquire_address(charon->attributes, 
									config->get_pool(config),
									this->ike_sa->get_other_id(this->ike_sa),
									this->ike_sa->get_other_auth(this->ike_sa),
									this->virtual_ip);
			if (ip == NULL)
			{
				DBG1(DBG_IKE, "not assigning a virtual IP to peer");
				return SUCCESS;
			}
			DBG1(DBG_IKE, "assigning virtual IP %H to peer", ip);
			this->ike_sa->set_virtual_ip(this->ike_sa, FALSE, ip);
			
			this->virtual_ip->destroy(this->virtual_ip);
			this->virtual_ip = ip;
			
			build_payloads(this, message, CFG_REPLY);
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
	if (message->get_exchange_type(message) == IKE_AUTH &&
		!message->get_payload(message, EXTENSIBLE_AUTHENTICATION))
	{
		host_t *ip;
		peer_cfg_t *config;
		
		DESTROY_IF(this->virtual_ip);
		this->virtual_ip = NULL;

		process_payloads(this, message);
		
		if (this->virtual_ip == NULL)
		{	/* force a configured virtual IP, even server didn't return one */
			config = this->ike_sa->get_peer_cfg(this->ike_sa);
			this->virtual_ip = config->get_virtual_ip(config);
			if (this->virtual_ip)
			{
				this->virtual_ip = this->virtual_ip->clone(this->virtual_ip);
			}
		}

		if (this->virtual_ip && !this->virtual_ip->is_anyaddr(this->virtual_ip))
		{
			this->ike_sa->set_virtual_ip(this->ike_sa, TRUE, this->virtual_ip);
			
			while (this->dns->remove_last(this->dns, (void**)&ip) == SUCCESS)
			{
				if (!ip->is_anyaddr(ip))
				{
					this->ike_sa->add_dns_server(this->ike_sa, ip);
				}
				ip->destroy(ip);
			}
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
	this->dns->destroy_offset(this->dns, offsetof(host_t, destroy));
	
	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
	this->dns = linked_list_create();
}

/**
 * Implementation of task_t.destroy
 */
static void destroy(private_ike_config_t *this)
{
	DESTROY_IF(this->virtual_ip);
	this->dns->destroy_offset(this->dns, offsetof(host_t, destroy));
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
	this->initiator = initiator;
	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
	this->dns = linked_list_create();
	
	return &this->public;
}
