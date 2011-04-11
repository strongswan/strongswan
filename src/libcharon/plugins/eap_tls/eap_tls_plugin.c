/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "eap_tls_plugin.h"

#include "eap_tls.h"

#include <daemon.h>

METHOD(plugin_t, get_name, char*,
	eap_tls_plugin_t *this)
{
	return "eap-tls";
}

METHOD(plugin_t, destroy, void,
	eap_tls_plugin_t *this)
{
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_tls_create_server);
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_tls_create_peer);
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_tls_plugin_create()
{
	eap_tls_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.reload = (void*)return_false,
			.destroy = _destroy,
		},
	);

	charon->eap->add_method(charon->eap, EAP_TLS, 0, EAP_SERVER,
							(eap_constructor_t)eap_tls_create_server);
	charon->eap->add_method(charon->eap, EAP_TLS, 0, EAP_PEER,
							(eap_constructor_t)eap_tls_create_peer);

	return &this->plugin;
}
