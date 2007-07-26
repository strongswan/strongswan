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

#include <sys/stat.h>

#include <debug.h>

#include "dumm.h"

typedef struct private_dumm_t private_dumm_t;

struct private_dumm_t {
	dumm_t public;
	linked_list_t *guests;
};

static guest_t* create_guest(private_dumm_t *this, char *name, char *master, int mem)
{
	guest_t *guest;
	
	guest = guest_create(name, master, mem);
	if (guest)
	{
		this->guests->insert_last(this->guests, guest);
	}
	return guest;
}

static iterator_t* create_guest_iterator(private_dumm_t *this)
{
	return this->guests->create_iterator(this->guests, TRUE);
}

static void destroy(private_dumm_t *this)
{
	this->guests->destroy_offset(this->guests, offsetof(guest_t, destroy));
	free(this);
}

/**
 * check for a directory, create if it does not exist
 */
static bool makedir(char *dir)
{
	struct stat st;
	
	if (stat(dir, &st) != 0)
	{
		return mkdir(dir, S_IRWXU) == 0;
	}
	return S_ISDIR(st.st_mode);
}

dumm_t *dumm_create()
{
	private_dumm_t *this = malloc_thing(private_dumm_t);
	
	this->public.create_guest = (void*)create_guest;
	this->public.create_guest_iterator = (void*)create_guest_iterator;
	this->public.destroy = (void*)destroy;
	
	if (!makedir(HOST_DIR) || !makedir(MOUNT_DIR) || !makedir(RUN_DIR))
	{
		free(this);
		return NULL;
	}
	
	this->guests = linked_list_create();
	return &this->public;
}

