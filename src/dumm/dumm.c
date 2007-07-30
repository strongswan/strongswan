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

#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>

#include <debug.h>

#include "dumm.h"

typedef struct private_dumm_t private_dumm_t;

struct private_dumm_t {
	/** public dumm interface */
	dumm_t public;
	/** working dir */
	char *dir;
	/** list of managed guests */
	linked_list_t *guests;
	/** list of managed bridges */
	linked_list_t *bridges;
	/** do not catch signals if we are destroying */
	bool destroying;
};

/**
 * Implementation of dumm_t.create_guest.
 */
static guest_t* create_guest(private_dumm_t *this, char *name, char *kernel, 
							 char *master, int mem)
{
	guest_t *guest;
	
	guest = guest_create(this->dir, name, kernel, master, mem);
	if (guest)
	{
		this->guests->insert_last(this->guests, guest);
	}
	return guest;
}

/**
 * Implementation of dumm_t.create_guest_iterator.
 */
static iterator_t* create_guest_iterator(private_dumm_t *this)
{
	return this->guests->create_iterator(this->guests, TRUE);
}

/**
 * Implementation of dumm_t.create_bridge.
 */
static bridge_t* create_bridge(private_dumm_t *this, char *name)
{
	bridge_t *bridge;
	
	bridge = bridge_create(name);
	if (bridge)
	{
		this->bridges->insert_last(this->bridges, bridge);
	}
	return bridge;
}

/**
 * Implementation of dumm_t.create_bridge_iterator.
 */
static iterator_t* create_bridge_iterator(private_dumm_t *this)
{
	return this->bridges->create_iterator(this->bridges, TRUE);
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

/**
 * Implementation of dumm_t.destroy
 */
static void destroy(private_dumm_t *this)
{
	iterator_t *iterator;
	guest_t *guest;

	this->bridges->destroy_offset(this->bridges, offsetof(bridge_t, destroy));
	
	iterator = this->guests->create_iterator(this->guests, TRUE);
	while (iterator->iterate(iterator, (void**)&guest))
	{
		guest->stop(guest);
	}
	iterator->destroy(iterator);
	
	this->destroying = TRUE;
	this->guests->destroy_offset(this->guests, offsetof(guest_t, destroy));
	free(this->dir);
	free(this);
}

/**
 * load all guests in our working dir
 */
static void load_guests(private_dumm_t *this)
{
	DIR *dir;
	struct dirent *ent;
	guest_t *guest;
	
	dir = opendir(this->dir);
	if (dir == NULL)
	{
		return;
	}
	
	while ((ent = readdir(dir)))
	{
		if (streq(ent->d_name, ".") ||  streq(ent->d_name, ".."))
		{
			continue;
		}
		guest = guest_load(this->dir, ent->d_name);
		if (guest)
		{
			this->guests->insert_last(this->guests, guest);
		}
		else
		{
			DBG1("loading guest in directory '%s' failed, skipped", ent->d_name);
		}
	}
	closedir(dir);
}

/**
 * create a dumm instance
 */
dumm_t *dumm_create(char *dir)
{
	char cwd[PATH_MAX];
	private_dumm_t *this = malloc_thing(private_dumm_t);
	
	this->public.create_guest = (guest_t*(*)(dumm_t*,char*,char*,char*,int))create_guest;
	this->public.create_guest_iterator = (iterator_t*(*)(dumm_t*))create_guest_iterator;
	this->public.create_bridge = (bridge_t*(*)(dumm_t*, char *name))create_bridge;
	this->public.create_bridge_iterator = (iterator_t*(*)(dumm_t*))create_bridge_iterator;
	this->public.sigchild_handler = (void(*)(dumm_t*, siginfo_t *info))sigchild_handler;
	this->public.destroy = (void(*)(dumm_t*))destroy;
	
	this->destroying = FALSE;
	if (*dir == '/' || getcwd(cwd, sizeof(cwd)) == 0)
	{
		this->dir = strdup(dir);
	}
	else
	{
		asprintf(&this->dir, "%s/%s", cwd, dir);
	}
	this->guests = linked_list_create();
	this->bridges = linked_list_create();
	
	load_guests(this);
	return &this->public;
}

