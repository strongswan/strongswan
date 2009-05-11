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

#ifndef COWFS_H
#define COWFS_H

#include <library.h>

typedef struct cowfs_t cowfs_t;

/**
 * cowfs - Copy on write FUSE filesystem.
 *
 */
struct cowfs_t {
	
	/**
	 * Set an additional copy on write overlay.
	 *
	 * @param path		path of the overlay
	 * @return 			FALSE if failed
	 */
	bool (*set_overlay)(cowfs_t *this, char *path);
	
	/**
	 * Stop, umount and destroy a cowfs FUSE filesystem.
	 */
	void (*destroy) (cowfs_t *this);
};

/**
 * Mount a cowfs FUSE filesystem.
 *
 * @param master		read only master file system directory
 * @param host			copy on write host directory
 * @param mount			mountpoint where union is mounted
 * @return				instance, or NULL if FUSE initalization failed
 */
cowfs_t *cowfs_create(char *master, char *host, char *mount);

#endif /* COWFS_H */

