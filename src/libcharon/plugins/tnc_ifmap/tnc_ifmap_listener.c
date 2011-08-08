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

METHOD(listener_t, ike_updown, bool,
	private_tnc_ifmap_listener_t *this, ike_sa_t *ike_sa, bool up)
{
	u_int32_t ike_sa_id;
	identification_t *id;
	host_t *host;

	ike_sa_id = ike_sa->get_unique_id(ike_sa);
	id = ike_sa->get_other_id(ike_sa);
	host = ike_sa->get_other_host(ike_sa);

	DBG2(DBG_TNC, "sending ifmap->publish");
	if (!this->ifmap->publish(this->ifmap, ike_sa_id, id, host, up))
	{
		DBG1(DBG_TNC, "ifmap->publish with MAP server failed");
	}

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
tnc_ifmap_listener_t *tnc_ifmap_listener_create()
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

	DBG2(DBG_TNC, "sending ifmap->newSession");
	if (!this->ifmap->newSession(this->ifmap))
	{
		DBG1(DBG_TNC, "ifmap->newSession with MAP server failed");
		destroy(this);
		return NULL;
	}

	DBG2(DBG_TNC, "sending ifmap->purgePublisher");
	if (!this->ifmap->purgePublisher(this->ifmap))
	{
		DBG1(DBG_TNC, "ifmap->purgePublisher with MAP server failed");
		destroy(this);
		return NULL;
	}

	return &this->public;
}

