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
#include <hydra.h>
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
	 * list of attributes requested and its handler, entry_t
	 */
	linked_list_t *requested;
};

/**
 * Entry for a requested attribute and the requesting handler
 */
typedef struct {
	/** attribute requested */
	configuration_attribute_type_t type;
	/** handler requesting this attribute */
	attribute_handler_t *handler;
} entry_t;

/**
 * build INTERNAL_IPV4/6_ADDRESS attribute from virtual ip
 */
static configuration_attribute_t *build_vip(host_t *vip)
{
	configuration_attribute_type_t type;
	chunk_t chunk, prefix;

	if (vip->get_family(vip) == AF_INET)
	{
		type = INTERNAL_IP4_ADDRESS;
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
		type = INTERNAL_IP6_ADDRESS;
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
	return configuration_attribute_create_value(type, chunk);
}

/**
 * Handle a received attribute as initiator
 */
static void handle_attribute(private_ike_config_t *this,
							 configuration_attribute_t *ca)
{
	attribute_handler_t *handler = NULL;
	enumerator_t *enumerator;
	entry_t *entry;

	/* find the handler which requested this attribute */
	enumerator = this->requested->create_enumerator(this->requested);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->type == ca->get_type(ca))
		{
			handler = entry->handler;
			this->requested->remove_at(this->requested, enumerator);
			free(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* and pass it to the handle function */
	handler = hydra->attributes->handle(hydra->attributes,
							this->ike_sa->get_other_id(this->ike_sa), handler,
							ca->get_type(ca), ca->get_value(ca));
	if (handler)
	{
		this->ike_sa->add_configuration_attribute(this->ike_sa,
				handler, ca->get_type(ca), ca->get_value(ca));
	}
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
		case INTERNAL_IP4_SERVER:
		case INTERNAL_IP6_SERVER:
			/* assume it's a Windows client if we see proprietary attributes */
			this->ike_sa->enable_extension(this->ike_sa, EXT_MS_WINDOWS);
			/* fall */
		default:
		{
			if (this->initiator)
			{
				handle_attribute(this, ca);
			}
		}
	}
}

/**
 * Scan for configuration payloads and attributes
 */
static void process_payloads(private_ike_config_t *this, message_t *message)
{
	enumerator_t *enumerator, *attributes;
	payload_t *payload;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == CONFIGURATION)
		{
			cp_payload_t *cp = (cp_payload_t*)payload;
			configuration_attribute_t *ca;

			switch (cp->get_type(cp))
			{
				case CFG_REQUEST:
				case CFG_REPLY:
				{
					attributes = cp->create_attribute_enumerator(cp);
					while (attributes->enumerate(attributes, &ca))
					{
						DBG2(DBG_IKE, "processing %N attribute",
							 configuration_attribute_type_names, ca->get_type(ca));
						process_attribute(this, ca);
					}
					attributes->destroy(attributes);
					break;
				}
				default:
					DBG1(DBG_IKE, "ignoring %N config payload",
						 config_type_names, cp->get_type(cp));
					break;
			}
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(task_t, build_i, status_t,
	private_ike_config_t *this, message_t *message)
{
	if (message->get_message_id(message) == 1)
	{	/* in first IKE_AUTH only */
		cp_payload_t *cp = NULL;
		enumerator_t *enumerator;
		attribute_handler_t *handler;
		peer_cfg_t *config;
		configuration_attribute_type_t type;
		chunk_t data;
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
			cp = cp_payload_create_type(CFG_REQUEST);
			cp->add_attribute(cp, build_vip(vip));
		}

		enumerator = hydra->attributes->create_initiator_enumerator(hydra->attributes,
								this->ike_sa->get_other_id(this->ike_sa), vip);
		while (enumerator->enumerate(enumerator, &handler, &type, &data))
		{
			configuration_attribute_t *ca;
			entry_t *entry;

			/* create configuration attribute */
			DBG2(DBG_IKE, "building %N attribute",
				 configuration_attribute_type_names, type);
			ca = configuration_attribute_create_value(type, data);
			if (!cp)
			{
				cp = cp_payload_create_type(CFG_REQUEST);
			}
			cp->add_attribute(cp, ca);

			/* save handler along with requested type */
			entry = malloc_thing(entry_t);
			entry->type = type;
			entry->handler = handler;

			this->requested->insert_last(this->requested, entry);
		}
		enumerator->destroy(enumerator);

		if (cp)
		{
			message->add_payload(message, (payload_t*)cp);
		}
	}
	return NEED_MORE;
}

METHOD(task_t, process_r, status_t,
	private_ike_config_t *this, message_t *message)
{
	if (message->get_message_id(message) == 1)
	{	/* in first IKE_AUTH only */
		process_payloads(this, message);
	}
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_ike_config_t *this, message_t *message)
{
	if (this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{	/* in last IKE_AUTH exchange */
		enumerator_t *enumerator;
		configuration_attribute_type_t type;
		chunk_t value;
		host_t *vip = NULL;
		cp_payload_t *cp = NULL;
		peer_cfg_t *config;
		identification_t *id;

		id = this->ike_sa->get_other_eap_id(this->ike_sa);

		config = this->ike_sa->get_peer_cfg(this->ike_sa);
		if (this->virtual_ip)
		{
			DBG1(DBG_IKE, "peer requested virtual IP %H", this->virtual_ip);
			if (config->get_pool(config))
			{
				vip = hydra->attributes->acquire_address(hydra->attributes,
							config->get_pool(config), id, this->virtual_ip);
			}
			if (vip == NULL)
			{
				DBG1(DBG_IKE, "no virtual IP found, sending %N",
					 notify_type_names, INTERNAL_ADDRESS_FAILURE);
				message->add_notify(message, FALSE, INTERNAL_ADDRESS_FAILURE,
									chunk_empty);
				return SUCCESS;
			}
			DBG1(DBG_IKE, "assigning virtual IP %H to peer '%Y'", vip, id);
			this->ike_sa->set_virtual_ip(this->ike_sa, FALSE, vip);

			cp = cp_payload_create_type(CFG_REPLY);
			cp->add_attribute(cp, build_vip(vip));
		}

		/* query registered providers for additional attributes to include */
		enumerator = hydra->attributes->create_responder_enumerator(
						hydra->attributes, config->get_pool(config), id, vip);
		while (enumerator->enumerate(enumerator, &type, &value))
		{
			if (!cp)
			{
				cp = cp_payload_create_type(CFG_REPLY);
			}
			DBG2(DBG_IKE, "building %N attribute",
				 configuration_attribute_type_names, type);
			cp->add_attribute(cp,
						configuration_attribute_create_value(type, value));
		}
		enumerator->destroy(enumerator);

		if (cp)
		{
			message->add_payload(message, (payload_t*)cp);
		}
		DESTROY_IF(vip);
		return SUCCESS;
	}
	return NEED_MORE;
}

METHOD(task_t, process_i, status_t,
	private_ike_config_t *this, message_t *message)
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

METHOD(task_t, get_type, task_type_t,
	private_ike_config_t *this)
{
	return IKE_CONFIG;
}

METHOD(task_t, migrate, void,
	private_ike_config_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->virtual_ip);

	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
	this->requested->destroy_function(this->requested, free);
	this->requested = linked_list_create();
}

METHOD(task_t, destroy, void,
	private_ike_config_t *this)
{
	DESTROY_IF(this->virtual_ip);
	this->requested->destroy_function(this->requested, free);
	free(this);
}

/*
 * Described in header.
 */
ike_config_t *ike_config_create(ike_sa_t *ike_sa, bool initiator)
{
	private_ike_config_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
		.requested = linked_list_create(),
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}

