/*
 * Copyright (C) 2010 Tobias Brunner
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

#include <hildon-cp-plugin/hildon-cp-plugin-interface.h>

/**
 * main callback for control panel plugins
 */
osso_return_t execute(osso_context_t *osso, gpointer data,
					  gboolean user_activated)
{
	if (!user_activated)
	{
		/* load state */
	}

	return OSSO_OK;
}

/**
 * callback called in case state has to be saved
 */
osso_return_t save_state(osso_context_t *osso, gpointer data)
{
	/* save state */
	return OSSO_OK;
}

