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
	bool destroying;
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
	
/**
 * Implementation of dumm_t.sigchild_handler.
 */
static void sigchild_handler(private_dumm_t *this, siginfo_t *info)
{
	if (this->destroying)
	{
		return;
	}

	switch (info->si_code)
	{
		case CLD_EXITED:
		case CLD_KILLED:
		case CLD_DUMPED:
		case CLD_STOPPED:
		{
			iterator_t *iterator;
			guest_t *guest;
			
			iterator = this->guests->create_iterator(this->guests, TRUE);
			while (iterator->iterate(iterator, (void**)&guest))
			{
				if (guest->get_pid(guest) == info->si_pid)
				{
					guest->sigchild(guest);
					break;
				}
			}
			iterator->destroy(iterator);
			break;
		}
		default:
			break;
	}
}

static void destroy(private_dumm_t *this)
{
	iterator_t *iterator;
	guest_t *guest;

	iterator = this->guests->create_iterator(this->guests, TRUE);
	while (iterator->iterate(iterator, (void**)&guest))
	{
		guest->stop(guest);
	}
	iterator->destroy(iterator);
	
	this->destroying = TRUE;
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
	
	this->public.sigchild_handler = (void(*)(dumm_t*, siginfo_t *info))sigchild_handler;
	this->public.create_guest = (void*)create_guest;
	this->public.create_guest_iterator = (void*)create_guest_iterator;
	this->public.destroy = (void*)destroy;
	
	if (!makedir(HOST_DIR) || !makedir(MOUNT_DIR) || !makedir(RUN_DIR))
	{
		free(this);
		return NULL;
	}
	
	this->destroying = FALSE;
	this->guests = linked_list_create();
	return &this->public;
}

