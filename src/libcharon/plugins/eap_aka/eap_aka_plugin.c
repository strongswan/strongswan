/*
 * Copyright (C) 2008-2009 Martin Willi
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

#include "eap_aka_plugin.h"

#include "eap_aka_peer.h"
#include "eap_aka_server.h"

#include <daemon.h>
#include <simaka_manager.h>

typedef struct private_eap_aka_plugin_t private_eap_aka_plugin_t;

/**
 * Private data of an eap_sim_plugin_t object.
 */
struct private_eap_aka_plugin_t {

	/**
	 * Public interface.
	 */
	eap_aka_plugin_t public;

	/**
	 * EAP-AKA backend manager
	 */
	simaka_manager_t *mgr;
};

METHOD(plugin_t, get_name, char*,
	private_eap_aka_plugin_t *this)
{
	return "eap-aka";
}

METHOD(plugin_t, destroy, void,
	private_eap_aka_plugin_t *this)
{
	lib->set(lib, "aka-manager", NULL);
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_aka_server_create);
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_aka_peer_create);
	this->mgr->destroy(this->mgr);
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_aka_plugin_create()
{
	private_eap_aka_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.reload = (void*)return_false,
				.destroy = _destroy,
			},
		},
		.mgr = simaka_manager_create(),
	);

	charon->eap->add_method(charon->eap, EAP_AKA, 0, EAP_SERVER,
							(eap_constructor_t)eap_aka_server_create);
	charon->eap->add_method(charon->eap, EAP_AKA, 0, EAP_PEER,
							(eap_constructor_t)eap_aka_peer_create);
	lib->set(lib, "aka-manager", this->mgr);

	return &this->public.plugin;
}
