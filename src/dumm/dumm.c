/*
 * Copyright (C) 2008-2009 Tobias Brunner
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

#define PERME (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)
#define GUEST_DIR "guests"
#define TEMPLATE_DIR "templates"

typedef struct private_dumm_t private_dumm_t;

struct private_dumm_t {
	/** public dumm interface */
	dumm_t public;
	/** working dir */
	char *dir;
	/** directory of guests */
	char *guest_dir;
	/** directory of loaded template */
	char *template;
	/** list of managed guests */
	linked_list_t *guests;
	/** list of managed bridges */
	linked_list_t *bridges;
};

/**
 * Implementation of dumm_t.create_guest.
 */
static guest_t* create_guest(private_dumm_t *this, char *name, char *kernel,
							 char *master, char *args)
{
	guest_t *guest;

	guest = guest_create(this->guest_dir, name, kernel, master, args);
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
			ignore_result(system(buf));
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
 * Implementation of dumm_t.add_overlay.
 */
static bool add_overlay(private_dumm_t *this, char *dir)
{
	enumerator_t *enumerator;
	guest_t *guest;

	if (dir == NULL)
	{
		return TRUE;
	}
	if (strlen(dir) > PATH_MAX)
	{
		DBG1(DBG_LIB, "overlay directory string '%s' is too long", dir);
		return FALSE;
	}
	if (access(dir, F_OK) != 0)
	{
		if (!mkdir_p(dir, PERME))
		{
			DBG1(DBG_LIB, "creating overlay directory '%s' failed: %m", dir);
			return FALSE;
		}
	}
	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		char guest_dir[PATH_MAX];
		int len = snprintf(guest_dir, sizeof(guest_dir), "%s/%s", dir,
						   guest->get_name(guest));
		if (len < 0 || len >= sizeof(guest_dir))
		{
			goto error;
		}
		if (access(guest_dir, F_OK) != 0)
		{
			if (!mkdir_p(guest_dir, PERME))
			{
				DBG1(DBG_LIB, "creating overlay directory for guest '%s' failed: %m",
					 guest->get_name(guest));
				goto error;
			}
		}
		if (!guest->add_overlay(guest, guest_dir))
		{
			goto error;
		}
	}
	enumerator->destroy(enumerator);
	return TRUE;
error:
	enumerator->destroy(enumerator);
	this->public.del_overlay(&this->public, dir);
	return FALSE;
}

/**
 * Implementation of dumm_t.del_overlay.
 */
static bool del_overlay(private_dumm_t *this, char *dir)
{
	bool ret = FALSE;
	enumerator_t *enumerator;
	guest_t *guest;

	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		char guest_dir[PATH_MAX];
		int len = snprintf(guest_dir, sizeof(guest_dir), "%s/%s", dir,
						   guest->get_name(guest));
		if (len < 0 || len >= sizeof(guest_dir))
		{
			continue;
		}
		ret = guest->del_overlay(guest, guest_dir) || ret;
	}
	enumerator->destroy(enumerator);
	return ret;
}

/**
 * Implementation of dumm_t.pop_overlay.
 */
static bool pop_overlay(private_dumm_t *this)
{
	bool ret = FALSE;
	enumerator_t *enumerator;
	guest_t *guest;

	enumerator = this->guests->create_enumerator(this->guests);
	while (enumerator->enumerate(enumerator, (void**)&guest))
	{
		ret = guest->pop_overlay(guest) || ret;
	}
	enumerator->destroy(enumerator);
	return ret;
}

/**
 * disable the currently enabled template
 */
static void clear_template(private_dumm_t *this)
{
	if (this->template)
	{
		del_overlay(this, this->template);
		free(this->template);
		this->template = NULL;
	}
}

/**
 * Implementation of dumm_t.load_template.
 */
static bool load_template(private_dumm_t *this, char *name)
{
	clear_template(this);
	if (name == NULL)
	{
		return TRUE;
	}
	if (strlen(name) > PATH_MAX)
	{
		DBG1(DBG_LIB, "template name '%s' is too long", name);
		return FALSE;
	}
	if (strchr(name, '/') != NULL)
	{
		DBG1(DBG_LIB, "template name '%s' must not contain '/' characters", name);
		return FALSE;
	}
	if (asprintf(&this->template, "%s/%s", TEMPLATE_DIR, name) < 0)
	{
		this->template = NULL;
		return FALSE;
	}
	if (access(this->template, F_OK) != 0)
	{
		if (!mkdir_p(this->template, PERME))
		{
			DBG1(DBG_LIB, "creating template directory '%s' failed: %m",
				 this->template);
			return FALSE;
		}
	}
	return add_overlay(this, this->template);
}

/**
 * Template directory enumerator
 */
typedef struct {
	/** implements enumerator_t */
	enumerator_t public;
	/** directory enumerator */
	enumerator_t *inner;
} template_enumerator_t;

/**
 * Implementation of template_enumerator_t.enumerate.
 */
static bool template_enumerate(template_enumerator_t *this, char **template)
{
	struct stat st;
	char *rel;

	while (this->inner->enumerate(this->inner, &rel, NULL, &st))
	{
		if (S_ISDIR(st.st_mode) && *rel != '.')
		{
			*template = rel;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Implementation of template_enumerator_t.destroy.
 */
static void template_enumerator_destroy(template_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of dumm_t.create_template_enumerator.
 */
static enumerator_t* create_template_enumerator(private_dumm_t *this)
{
	template_enumerator_t *enumerator;
	enumerator = malloc_thing(template_enumerator_t);
	enumerator->public.enumerate = (void*)template_enumerate;
	enumerator->public.destroy = (void*)template_enumerator_destroy;
	enumerator->inner = enumerator_create_directory(TEMPLATE_DIR);
	if (!enumerator->inner)
	{
		free(enumerator);
		return enumerator_create_empty();
	}
	return &enumerator->public;
}

/**
 * Implementation of dumm_t.destroy.
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

	while (this->guests->remove_last(this->guests, (void**)&guest) == SUCCESS)
	{
		guest->destroy(guest);
	}
	this->guests->destroy(this->guests);
	free(this->guest_dir);
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
		if (*ent->d_name == '.')
		{	/* skip ".", ".." and hidden files (such as ".svn") */
			continue;
		}
		guest = guest_load(this->guest_dir, ent->d_name);
		if (guest)
		{
			this->guests->insert_last(this->guests, guest);
		}
		else
		{
			DBG1(DBG_LIB, "loading guest in directory '%s' failed, skipped",
				 ent->d_name);
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

	this->public.create_guest = (guest_t*(*)(dumm_t*,char*,char*,char*,char*))create_guest;
	this->public.create_guest_enumerator = (enumerator_t*(*)(dumm_t*))create_guest_enumerator;
	this->public.delete_guest = (void(*)(dumm_t*,guest_t*))delete_guest;
	this->public.create_bridge = (bridge_t*(*)(dumm_t*, char *name))create_bridge;
	this->public.create_bridge_enumerator = (enumerator_t*(*)(dumm_t*))create_bridge_enumerator;
	this->public.delete_bridge = (void(*)(dumm_t*,bridge_t*))delete_bridge;
	this->public.add_overlay = (bool(*)(dumm_t*,char*))add_overlay;
	this->public.del_overlay = (bool(*)(dumm_t*,char*))del_overlay;
	this->public.pop_overlay = (bool(*)(dumm_t*))pop_overlay;
	this->public.load_template = (bool(*)(dumm_t*,char*))load_template;
	this->public.create_template_enumerator = (enumerator_t*(*)(dumm_t*))create_template_enumerator;
	this->public.destroy = (void(*)(dumm_t*))destroy;

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
			if (asprintf(&this->dir, "%s/%s", cwd, dir) < 0)
			{
				this->dir = NULL;
			}
		}
		else
		{
			this->dir = strdup(cwd);
		}
	}
	this->template = NULL;
	if (asprintf(&this->guest_dir, "%s/%s", this->dir, GUEST_DIR) < 0)
	{
		this->guest_dir = NULL;
	}
	this->guests = linked_list_create();
	this->bridges = linked_list_create();

	if (this->dir == NULL || this->guest_dir == NULL ||
		(mkdir(this->guest_dir, PERME) < 0 && errno != EEXIST))
	{
		DBG1(DBG_LIB, "creating guest directory '%s' failed: %m",
			 this->guest_dir);
		destroy(this);
		return NULL;
	}

	load_guests(this);
	return &this->public;
}

