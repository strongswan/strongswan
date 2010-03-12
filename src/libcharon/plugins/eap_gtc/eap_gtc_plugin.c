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

#include "eap_gtc_plugin.h"

#include "eap_gtc.h"

#include <daemon.h>

/* missing in cababilities.h */
#define CAP_AUDIT_WRITE 29

/**
 * Implementation of plugin_t.destroy
 */
static void destroy(eap_gtc_plugin_t *this)
{
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_gtc_create_server);
	charon->eap->remove_method(charon->eap,
							   (eap_constructor_t)eap_gtc_create_peer);
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_gtc_plugin_create()
{
	eap_gtc_plugin_t *this = malloc_thing(eap_gtc_plugin_t);

	this->plugin.destroy = (void(*)(plugin_t*))destroy;

	/* required for PAM authentication */
	charon->keep_cap(charon, CAP_AUDIT_WRITE);

	charon->eap->add_method(charon->eap, EAP_GTC, 0, EAP_SERVER,
							(eap_constructor_t)eap_gtc_create_server);
	charon->eap->add_method(charon->eap, EAP_GTC, 0, EAP_PEER,
							(eap_constructor_t)eap_gtc_create_peer);

	return &this->plugin;
}

