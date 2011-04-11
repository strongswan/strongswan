/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "tnccs_11_plugin.h"
#include "tnccs_11.h"

#include <daemon.h>

METHOD(plugin_t, get_name, char*,
	tnccs_11_plugin_t *this)
{
	return "tnccs-11";
}

METHOD(plugin_t, destroy, void,
	tnccs_11_plugin_t *this)
{
	charon->tnccs->remove_method(charon->tnccs,
								(tnccs_constructor_t)tnccs_11_create);
	free(this);
}

/*
 * see header file
 */
plugin_t *tnccs_11_plugin_create()
{
	tnccs_11_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.reload = (void*)return_false,
			.destroy = _destroy,
		},
	);

	charon->tnccs->add_method(charon->tnccs, TNCCS_1_1,
							 (tnccs_constructor_t)tnccs_11_create);

	return &this->plugin;
}

