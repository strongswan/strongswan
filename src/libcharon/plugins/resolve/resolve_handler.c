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

#include "resolve_handler.h"

#include <unistd.h>

#include <daemon.h>
#include <threading/mutex.h>

typedef struct private_resolve_handler_t private_resolve_handler_t;

/**
 * Private data of an resolve_handler_t object.
 */
struct private_resolve_handler_t {

	/**
	 * Public resolve_handler_t interface.
	 */
	resolve_handler_t public;

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
static bool handle(private_resolve_handler_t *this, identification_t *server,
				   configuration_attribute_type_t type, chunk_t data)
{
	FILE *in, *out;
	char buf[1024];
	host_t *addr;
	size_t len;
	bool handled = FALSE;

	switch (type)
	{
		case INTERNAL_IP4_DNS:
			addr = host_create_from_chunk(AF_INET, data, 0);
			break;
		case INTERNAL_IP6_DNS:
			addr = host_create_from_chunk(AF_INET6, data, 0);
			break;
		default:
			return FALSE;
	}

	if (!addr || addr->is_anyaddr(addr))
	{
		DESTROY_IF(addr);
		return FALSE;
	}
	this->mutex->lock(this->mutex);

	in = fopen(this->file, "r");
	/* allows us to stream from in to out */
	unlink(this->file);
	out = fopen(this->file, "w");
	if (out)
	{
		fprintf(out, "nameserver %H   # by strongSwan, from %Y\n", addr, server);
		DBG1(DBG_IKE, "installing DNS server %H to %s", addr, this->file);
		handled = TRUE;

		/* copy rest of the file */
		if (in)
		{
			while ((len = fread(buf, 1, sizeof(buf), in)))
			{
				ignore_result(fwrite(buf, 1, len, out));
			}
		}
		fclose(out);
	}
	if (in)
	{
		fclose(in);
	}
	this->mutex->unlock(this->mutex);
	addr->destroy(addr);

	if (!handled)
	{
		DBG1(DBG_IKE, "adding DNS server failed", this->file);
	}
	return handled;
}

/**
 * Implementation of attribute_handler_t.release
 */
static void release(private_resolve_handler_t *this, identification_t *server,
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
					 addr, server);

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
 * Attribute enumerator implementation
 */
typedef struct {
	/** implements enumerator_t interface */
	enumerator_t public;
	/** virtual IP we are requesting */
	host_t *vip;
} attribute_enumerator_t;

/**
 * Implementation of create_attribute_enumerator().enumerate()
 */
static bool attribute_enumerate(attribute_enumerator_t *this,
						configuration_attribute_type_t *type, chunk_t *data)
{
	switch (this->vip->get_family(this->vip))
	{
		case AF_INET:
			*type = INTERNAL_IP4_DNS;
			break;
		case AF_INET6:
			*type = INTERNAL_IP6_DNS;
			break;
		default:
			return FALSE;
	}
	*data = chunk_empty;
	/* enumerate only once */
	this->public.enumerate = (void*)return_false;
	return TRUE;
}

/**
 * Implementation of attribute_handler_t.create_attribute_enumerator
 */
static enumerator_t* create_attribute_enumerator(private_resolve_handler_t *this,
										identification_t *server, host_t *vip)
{
	if (vip)
	{
		attribute_enumerator_t *enumerator;

		enumerator = malloc_thing(attribute_enumerator_t);
		enumerator->public.enumerate = (void*)attribute_enumerate;
		enumerator->public.destroy = (void*)free;
		enumerator->vip = vip;

		return &enumerator->public;
	}
	return enumerator_create_empty();
}

/**
 * Implementation of resolve_handler_t.destroy.
 */
static void destroy(private_resolve_handler_t *this)
{
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
resolve_handler_t *resolve_handler_create()
{
	private_resolve_handler_t *this = malloc_thing(private_resolve_handler_t);

	this->public.handler.handle = (bool(*)(attribute_handler_t*, identification_t*, configuration_attribute_type_t, chunk_t))handle;
	this->public.handler.release = (void(*)(attribute_handler_t*, identification_t*, configuration_attribute_type_t, chunk_t))release;
	this->public.handler.create_attribute_enumerator = (enumerator_t*(*)(attribute_handler_t*, identification_t *server, host_t *vip))create_attribute_enumerator;
	this->public.destroy = (void(*)(resolve_handler_t*))destroy;

	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->file = lib->settings->get_str(lib->settings,
								"charon.plugins.resolve.file", RESOLV_CONF);

	return &this->public;
}

