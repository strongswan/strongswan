/*
 * Copyright (C) 2007 Martin Willi
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

#ifndef BRIDGE_H
#define BRIDGE_H

#include <library.h>
#include <utils/iterator.h>

#include "iface.h"

typedef struct bridge_t bridge_t;

/**
 * @brief Interface in a guest, connected to a tap device on the host.
 */
struct bridge_t {
	
	/**
	 * @brief Get the name of the bridge.
	 *
	 * @return				name of the bridge
	 */
	char* (*get_name)(bridge_t *this);
	
	/**
	 * @brief Add an interface to a bridge.
	 *
	 * @param iface			interface to add
	 * @return				TRUE if interface added
	 */
	bool (*add_iface)(bridge_t *this, iface_t *iface);
	
	/**
	 * @brief Remove an interface from a bridge.
	 *
	 * @param iface			interface to remove
	 * @return				TRUE ifinterface removed
	 */
	bool (*del_iface)(bridge_t *this, iface_t *iface);
	
	/**
	 * @brief Create an iterator over all interfaces.
	 *
	 * @return 				iterator over iface_t's
	 */
	iterator_t* (*create_iface_iterator)(bridge_t *this);	
	
	/**
	 * @brief Destroy a bridge
	 */
	void (*destroy) (bridge_t *this);
};

/**
 * @brief Create a new bridge.
 *
 * @param name		name of the bridge to create
 * @return			bridge, NULL if failed
 */
bridge_t *bridge_create(char *name);

#endif /* BRIDGE_H */

