/*
 * Copyright (C) 2009 Martin Willi
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

#include "resolv_conf_handler.h"

#include <unistd.h>

#include <daemon.h>
#include <utils/mutex.h>

typedef struct private_resolv_conf_handler_t private_resolv_conf_handler_t;

/**
 * Private data of an resolv_conf_handler_t object.
 */
struct private_resolv_conf_handler_t {

	/**
	 * Public resolv_conf_handler_t interface.
	 */
	resolv_conf_handler_t public;

	/**
	 * resolv.conf file to use
	 */
	char *file;

	/**
	 * Mutex to access file exclusively
	 */
	mutex_t *mutex;
};

/**
 * Implementation of attribute_handler_t.handle
 */
static bool handle(private_resolv_conf_handler_t *this, ike_sa_t *ike_sa,
				   configuration_attribute_type_t type, chunk_t data)
{
	FILE *in, *out;
	char buf[1024];
	host_t *addr;
	int family;
	size_t len;
	bool handled = FALSE;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return FALSE;
	}

	this->mutex->lock(this->mutex);

	in = fopen(this->file, "r");
	/* allows us to stream from in to out */
	unlink(this->file);
	out = fopen(this->file, "w");
	if (out)
	{
		addr = host_create_from_chunk(family, data, 0);
		fprintf(out, "nameserver %H   # by strongSwan, from %Y\n",
				addr, ike_sa->get_other_id(ike_sa));
		DBG1(DBG_IKE, "installing DNS server %H to %s", addr, this->file);
		addr->destroy(addr);
		handled = TRUE;

		/* copy rest of the file */
		if (in)
		{
			while ((len = fread(buf, 1, sizeof(buf), in)))
			{
				ignore_result(fwrite(buf, 1, len, out));
			}
			fclose(in);
		}
		fclose(out);
	}

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed", this->file);
	}
	this->mutex->unlock(this->mutex);
	return handled;
}

/**
 * Implementation of attribute_handler_t.release
 */
static void release(private_resolv_conf_handler_t *this, ike_sa_t *ike_sa,
					configuration_attribute_type_t type, chunk_t data)
{
	FILE *in, *out;
	char line[1024], matcher[512], *pos;
	host_t *addr;
	int family;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			family = AF_INET;
			break;
		case INTERNAL_IP6_DNS:
			family = AF_INET6;
			break;
		default:
			return;
	}

	this->mutex->lock(this->mutex);

	in = fopen(this->file, "r");
	if (in)
	{
		/* allows us to stream from in to out */
		unlink(this->file);
		out = fopen(this->file, "w");
		if (out)
		{
			addr = host_create_from_chunk(family, data, 0);
			snprintf(matcher, sizeof(matcher),
					 "nameserver %H   # by strongSwan, from %Y\n",
					 addr, ike_sa->get_other_id(ike_sa));

			/* copy all, but matching line */
			while ((pos = fgets(line, sizeof(line), in)))
			{
				if (strneq(line, matcher, strlen(matcher)))
				{
					DBG1(DBG_IKE, "removing DNS server %H from %s",
						 addr, this->file);
				}
				else
				{
					fputs(line, out);
				}
			}
			addr->destroy(addr);
			fclose(out);
		}
		fclose(in);
	}

	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of resolv_conf_handler_t.destroy.
 */
static void destroy(private_resolv_conf_handler_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
resolv_conf_handler_t *resolv_conf_handler_create()
{
	private_resolv_conf_handler_t *this = malloc_thing(private_resolv_conf_handler_t);

	this->public.handler.handle = (bool(*)(attribute_handler_t*, ike_sa_t*, configuration_attribute_type_t, chunk_t))handle;
	this->public.handler.release = (void(*)(attribute_handler_t*, ike_sa_t*, configuration_attribute_type_t, chunk_t))release;
	this->public.destroy = (void(*)(resolv_conf_handler_t*))destroy;

	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->file = lib->settings->get_str(lib->settings,
								"charon.plugins.resolv-conf.file", RESOLV_CONF);

	return &this->public;
}

