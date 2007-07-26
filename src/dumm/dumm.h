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

#ifndef DUMM_H
#define DUMM_H

#include <library.h>
#include <utils/linked_list.h>

#include "guest.h"

#define HOST_DIR "host"
#define MOUNT_DIR "mount"
#define RUN_DIR "run"


typedef struct dumm_t dumm_t;

/**
 * @brief dumm - Dynamic Uml Mesh Modeler
 *
 * Controls a group of UML guests and their networks.
 */
struct dumm_t {

	/**
	 * @brief Starts a new UML guest
	 *
	 * @param name		name of the guest
	 * @param master	mounted read only master filesystem
	 * @param mem		amount of memory for guest, in MB
	 * @return			guest if started, NULL if failed
	 */
	guest_t* (*create_guest) (dumm_t *this, char *name, char *master, int mem);
	
	/**
	 * @brief Create an iterator over all guests.
	 *
	 * @return			iteraotor over guest_t's
	 */
	iterator_t* (*create_guest_iterator) (dumm_t *this);
	
	/**
	 * @brief stop all guests and destroy the modeler
	 */
	void (*destroy) (dumm_t *this);
};

/**
 * @brief Create a new group of UML hosts and networks.
 *
 * Dumm uses its working dir to create folders and files it works with.
 *
 * @return				created UML group, or NULL if failed.
 */
dumm_t *dumm_create();

#endif /* DUMM_H */

