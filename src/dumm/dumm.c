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
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>

#include <debug.h>
#include <utils/linked_list.h>

#include "dumm.h"

#define PERME (S_IRWXU | S_IRWXG)
#define GUEST_DIR "guests"
#define TEMPLATE_DIR "templates"
#define TEMPLATE_DIR_DIR "diff"

typedef struct private_dumm_t private_dumm_t;

struct private_dumm_t {
	/** public dumm interface */
	dumm_t public;
	/** working dir */
	char *dir;
	/** directory of guests */
	char *guest_dir;
	/** directory of templates */
	char *template_dir;
	/** directory of loaded template */
	char *template;
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
	
	guest = guest_create(this->guest_dir, name, kernel, master, mem);
	if (guest)
	{
		this->guests->insert_last(this->guests, guest);
	}
	return guest;
}

/**
 * Implementation of dumm_t.create_guest_enumerator.
 */
static enumerator_t* create_guest_enumerator(private_dumm_t *this)
{
	return this->guests->create_enumerator(this->guests);
}

/**
 * Implementation of dumm_t.delete_guest.
 */
static void delete_guest(private_dumm_t *this, guest_t *guest)
{
	if (this->guests->remove(this->guests, guest, NULL))
	{
		char buf[512];
		int len;
		
		len = snprintf(buf, sizeof(buf), "rm -Rf %s/%s",
					   this->guest_dir, guest->get_name(guest));
		guest->destroy(guest);
		if (len > 8 && len < 512)
		{
			system(buf);
		}
	}
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
 * Implementation of dumm_t.create_bridge_enumerator.
 */
static enumerator_t* create_bridge_enumerator(private_dumm_t *this)
{
	return this->bridges->create_enumerator(this->bridges);
}

/**
 * Implementation of dumm_t.delete_bridge.
 */
static void delete_bridge(private_dumm_t *this, bridge_t *bridge)
{
	if (this->bridges->remove(this->bridges, bridge, NULL))
	{
		bridge->destroy(bridge);
	}
}

/**
 * disable the currently enabled template 
 */
static void clear_template(private_dumm_t *this)
{
	enumerator_t *enumerator;
	guest_t *guest;

	free(this->template);
	this->template = NULL;

	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		guest->load_template(guest, NULL);
	}
	enumerator->destroy(enumerator);
}

/**
 * Implementation of dumm_t.load_template.
 */
static bool load_template(private_dumm_t *this, char *name)
{
	enumerator_t *enumerator;
	guest_t *guest;
	char dir[PATH_MAX];
	size_t len;
	
	clear_template(this);
	
	if (name == NULL)
	{
		return TRUE;
	}

	free(this->template);
	asprintf(&this->template, "%s/%s", this->template_dir, name);
	len = snprintf(dir, sizeof(dir), "%s/%s", this->template, TEMPLATE_DIR_DIR);
	if (len < 0 || len >= sizeof(dir))
	{
		return FALSE;
	}
	
	if (access(this->template, F_OK) != 0)
	{	/* does not exist, create template */
		if (mkdir(this->template, PERME) != 0)
		{
			DBG1("creating template directory '%s' failed: %m", this->template);
			return FALSE;
		}
		if (mkdir(dir, PERME) != 0)
		{
			DBG1("creating template overlay directory '%s' failed: %m", dir);
			return FALSE;
		}
	}
	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		if (!guest->load_template(guest, dir))
		{
			enumerator->destroy(enumerator);
			clear_template(this);
			return FALSE;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
}

/**
 * Implementation of dumm_t.destroy
 */
static void destroy(private_dumm_t *this)
{
	enumerator_t *enumerator;
	guest_t *guest;

	this->bridges->destroy_offset(this->bridges, offsetof(bridge_t, destroy));
	
	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		guest->stop(guest, NULL);
	}
	enumerator->destroy(enumerator);
	
	this->destroying = TRUE;
	this->guests->destroy_offset(this->guests, offsetof(guest_t, destroy));
	free(this->guest_dir);
	free(this->template_dir);
	free(this->template);
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
	
	dir = opendir(this->guest_dir);
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
		guest = guest_load(this->guest_dir, ent->d_name);
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
	this->public.create_guest_enumerator = (enumerator_t*(*)(dumm_t*))create_guest_enumerator;
	this->public.delete_guest = (void(*)(dumm_t*,guest_t*))delete_guest;
	this->public.create_bridge = (bridge_t*(*)(dumm_t*, char *name))create_bridge;
	this->public.create_bridge_enumerator = (enumerator_t*(*)(dumm_t*))create_bridge_enumerator;
	this->public.delete_bridge = (void(*)(dumm_t*,bridge_t*))delete_bridge;
	this->public.load_template = (bool(*)(dumm_t*, char *name))load_template;
	this->public.destroy = (void(*)(dumm_t*))destroy;
	
	this->destroying = FALSE;
	
	if (dir && *dir == '/')
	{
		this->dir = strdup(dir);
	}
	else
	{
	 	if (getcwd(cwd, sizeof(cwd)) == NULL)
	 	{
	 		free(this);
	 		return NULL;
	 	}
		if (dir)
		{
			asprintf(&this->dir, "%s/%s", cwd, dir);
		}
		else
		{
			this->dir = strdup(cwd);
		}
	}
	this->template = NULL;
	asprintf(&this->guest_dir, "%s/%s", this->dir, GUEST_DIR);
	asprintf(&this->template_dir, "%s/%s", this->dir, TEMPLATE_DIR);
	this->guests = linked_list_create();
	this->bridges = linked_list_create();
	
	if (mkdir(this->guest_dir, PERME) < 0 && errno != EEXIST)
	{
		DBG1("creating guest directory '%s' failed: %m", this->guest_dir);
		destroy(this);
		return NULL;
	}
	if (mkdir(this->template_dir, PERME) < 0 && errno != EEXIST)
	{
		DBG1("creating template directory '%s' failed: %m", this->template_dir);
		destroy(this);
		return NULL;
	}
	
	load_guests(this);
	return &this->public;
}

