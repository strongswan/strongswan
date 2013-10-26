/*
 * Copyright (C) 2008 Martin Willi
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

#include "tnc_pt_tls_listener.h"

#include <daemon.h>
#include <config/child_cfg.h>

typedef struct private_tnc_pt_tls_listener_t private_tnc_pt_tls_listener_t;

/**
 * Private data of an tnc_pt_tls_listener_t object.
 */
struct private_tnc_pt_tls_listener_t {

	/**
	 * Public tnc_pt_tls_listener_t interface.
	 */
	tnc_pt_tls_listener_t public;

	/**
	 * PT-TLS connection manager
	 */
	pt_tls_manager_t *mgr;
};

METHOD(listener_t, child_updown, bool,
	private_tnc_pt_tls_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	bool up)
{
	traffic_selector_t *my_ts, *other_ts;
	pt_tls_connection_t *connection;
	host_t *host;
	enumerator_t *e1, *e2;
	bool found = FALSE;

	e1 = this->mgr->create_connection_enumerator(this->mgr);
	while (e1->enumerate(e1, &connection))
	{
		host = connection->get_host(connection);

		e2 = child_sa->create_policy_enumerator(child_sa);
		while (e2->enumerate(e2, &my_ts, &other_ts))
		{
			if (other_ts->includes(other_ts, host))
			{
				if (up)
				{
					DBG1(DBG_TNC, "starting PT-TLS connection with %#H", host);
					connection->start(connection);
				}
				else
				{
					DBG1(DBG_TNC, "stopping PT-TLS connection with %#H", host);
					this->mgr->remove_connection(this->mgr, connection);
					connection->destroy(connection);
				}
				found = TRUE;
				break;
			}
		}
		e2->destroy(e2);

		if (found)
		{
			break;
		}
	}
	e1->destroy(e1);

	return TRUE;
}

METHOD(tnc_pt_tls_listener_t, destroy, void,
	private_tnc_pt_tls_listener_t *this)
{
	free(this);
}

/**
 * See header
 */
tnc_pt_tls_listener_t *tnc_pt_tls_listener_create(pt_tls_manager_t *mgr)
{
	private_tnc_pt_tls_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.child_updown = _child_updown,
			},
			.destroy = _destroy,
		},
		.mgr = mgr,
	);

	return &this->public;
}
