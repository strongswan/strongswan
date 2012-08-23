/*
 * Copyright (C) 2012 Tobias Brunner
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

#include "eap_dynamic.h"

#include <daemon.h>
#include <library.h>

typedef struct private_eap_dynamic_t private_eap_dynamic_t;

/**
 * Private data of an eap_dynamic_t object.
 */
struct private_eap_dynamic_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_dynamic_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * Our supported EAP types (as eap_vendor_type_t*)
	 */
	linked_list_t *types;

	/**
	 * The proxied EAP method
	 */
	eap_method_t *method;
};

/**
 * Load the given EAP method
 */
static eap_method_t *load_method(private_eap_dynamic_t *this,
								 eap_type_t type, u_int32_t vendor)
{
	eap_method_t *method;

	method = charon->eap->create_instance(charon->eap, type, vendor, EAP_SERVER,
										  this->server, this->peer);
	if (!method)
	{
		if (vendor)
		{
			DBG1(DBG_IKE, "loading vendor specific EAP method %d-%d failed",
				 type, vendor);
		}
		else
		{
			DBG1(DBG_IKE, "loading %N method failed", eap_type_names, type);
		}
	}
	return method;
}

/**
 * Select the first method we can instantiate
 */
static void select_method(private_eap_dynamic_t *this)
{
	eap_vendor_type_t *entry;

	while (this->types->remove_first(this->types, (void*)&entry) == SUCCESS)
	{
		this->method = load_method(this, entry->type, entry->vendor);
		free(entry);

		if (this->method)
		{
			break;
		}
	}
}

METHOD(eap_method_t, initiate, status_t,
	private_eap_dynamic_t *this, eap_payload_t **out)
{
	if (!this->method)
	{
		select_method(this);
		if (!this->method)
		{
			DBG1(DBG_IKE, "no supported EAP method found");
			return FAILED;
		}
	}
	return this->method->initiate(this->method, out);
}

METHOD(eap_method_t, process, status_t,
	private_eap_dynamic_t *this, eap_payload_t *in, eap_payload_t **out)
{
	if (this->method)
	{
		return this->method->process(this->method, in, out);
	}
	return FAILED;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_dynamic_t *this, u_int32_t *vendor)
{
	if (this->method)
	{
		return this->method->get_type(this->method, vendor);
	}
	*vendor = 0;
	return EAP_DYNAMIC;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_dynamic_t *this, chunk_t *msk)
{
	if (this->method)
	{
		return this->method->get_msk(this->method, msk);
	}
	return FAILED;
}

METHOD(eap_method_t, get_identifier, u_int8_t,
	private_eap_dynamic_t *this)
{
	if (this->method)
	{
		return this->method->get_identifier(this->method);
	}
	return 0;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_dynamic_t *this, u_int8_t identifier)
{
	if (this->method)
	{
		this->method->set_identifier(this->method, identifier);
	}
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_dynamic_t *this)
{
	if (this->method)
	{
		return this->method->is_mutual(this->method);
	}
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	private_eap_dynamic_t *this)
{
	DESTROY_IF(this->method);
	this->types->destroy_function(this->types, (void*)free);
	this->server->destroy(this->server);
	this->peer->destroy(this->peer);
	free(this);
}

/**
 * Get all supported EAP methods
 */
static void get_supported_eap_types(private_eap_dynamic_t *this)
{
	enumerator_t *enumerator;
	eap_type_t type;
	u_int32_t vendor;

	enumerator = charon->eap->create_enumerator(charon->eap, EAP_SERVER);
	while (enumerator->enumerate(enumerator, &type, &vendor))
	{
		eap_vendor_type_t *entry;

		INIT(entry,
			.type = type,
			.vendor = vendor,
		);
		this->types->insert_last(this->types, entry);
	}
	enumerator->destroy(enumerator);
}

/*
 * Defined in header
 */
eap_dynamic_t *eap_dynamic_create(identification_t *server,
								  identification_t *peer)
{
	private_eap_dynamic_t *this;

	INIT(this,
		.public = {
			.interface = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.types = linked_list_create(),
	);

	/* get all supported EAP methods */
	get_supported_eap_types(this);

	return &this->public;
}
