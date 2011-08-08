/*
 * Copyright (C) 2011 Andreas Steffen 
 * HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_ifmap_listener.h"
#include "tnc_ifmap_soap.h"

#include <daemon.h>
#include <hydra.h>
#include <debug.h>

typedef struct private_tnc_ifmap_listener_t private_tnc_ifmap_listener_t;

/**
 * Private data of an tnc_ifmap_listener_t object.
 */
struct private_tnc_ifmap_listener_t {

	/**
	 * Public tnc_ifmap_listener_t interface.
	 */
	tnc_ifmap_listener_t public;

	/**
	 * TNC IF-MAP 2.0 SOAP interface
	 */
	tnc_ifmap_soap_t *ifmap;

};

/**
 * Publish metadata of a single IKE_SA
 */
static bool publish_ike_sa(private_tnc_ifmap_listener_t *this,
						   ike_sa_t *ike_sa, bool up)
{
	u_int32_t ike_sa_id;
	identification_t *id, *eap_id;
	bool is_user;
	host_t *host;

	ike_sa_id = ike_sa->get_unique_id(ike_sa);
	id = ike_sa->get_other_id(ike_sa);
	eap_id = ike_sa->get_other_eap_id(ike_sa);
	host = ike_sa->get_other_host(ike_sa);

	/* In the presence of an EAP Identity, treat it as a username */
	is_user = !id->equals(id, eap_id);

	return this->ifmap->publish_ike_sa(this->ifmap, ike_sa_id, eap_id, is_user,
									   host, up);
}

/**
 * Publish PEP device-ip metadata
 */
static bool publish_device_ip_addresses(private_tnc_ifmap_listener_t *this)
{
	enumerator_t *enumerator;
	host_t *host;
	bool success = TRUE;

	enumerator = hydra->kernel_interface->create_address_enumerator(
							hydra->kernel_interface, FALSE, FALSE);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (!this->ifmap->publish_device_ip(this->ifmap, host))
		{
			success = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	return success;
}

/**
 * Publish all IKE_SA metadata
 */
static bool reload_metadata(private_tnc_ifmap_listener_t *this)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	bool success = TRUE;

	enumerator = charon->controller->create_ike_sa_enumerator(
												charon->controller, FALSE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		if (ike_sa->get_state(ike_sa) != IKE_ESTABLISHED)
		{
			continue;
		}
		if (!publish_ike_sa(this, ike_sa, TRUE))
		{
			success = FALSE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	
	return success;
}

METHOD(listener_t, ike_updown, bool,
	private_tnc_ifmap_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	publish_ike_sa(this, ike_sa, up);

	return TRUE;
}

METHOD(tnc_ifmap_listener_t, destroy, void,
	private_tnc_ifmap_listener_t *this)
{
	DESTROY_IF(this->ifmap);
	free(this);
}

/**
 * See header
 */
tnc_ifmap_listener_t *tnc_ifmap_listener_create(bool reload)
{
	private_tnc_ifmap_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.ike_updown = _ike_updown,
			},
			.destroy = _destroy,
		},
		.ifmap = tnc_ifmap_soap_create(),
	);

	if (!this->ifmap)
	{
		destroy(this);
		return NULL;
	}
	if (!this->ifmap->newSession(this->ifmap))
	{
		destroy(this);
		return NULL;
	}
	if (!this->ifmap->purgePublisher(this->ifmap))
	{
		destroy(this);
		return NULL;
	}
	if (!publish_device_ip_addresses(this))
	{
		destroy(this);
		return NULL;
	}
	if (reload)
	{
		if (!reload_metadata(this))
		{
			destroy(this);
			return NULL;
		}
	}

	return &this->public;
}

