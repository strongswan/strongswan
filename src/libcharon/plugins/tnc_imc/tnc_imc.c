/*
 * Copyright (C) 2006 Mike McCauley
 * Copyright (C) 2010 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include "tnc_imc.h"

#include <dlfcn.h>

#include <debug.h>
#include <library.h>
#include <threading/mutex.h>

typedef struct private_tnc_imc_t private_tnc_imc_t;

/**
 * Private data of an imc_t object.
 */
struct private_tnc_imc_t {

	/**
	 * Public members of imc_t.
	 */
	imc_t public;

	/**
	 * Path of loaded IMC
	 */
	char *path;

	/**
	 * Name of loaded IMC
	 */
	char *name;

	/**
	 * Handle of loaded IMC
	 */
	void *handle;

	/**
	 * ID of loaded IMC
	 */
	TNC_IMCID id;

	/**
	 * List of message types supported by IMC
	 */
	TNC_MessageTypeList supported_types;

	/**
	 * Number of supported message types
	 */
	TNC_UInt32 type_count;

	/**
	 * mutex to lock the imc_t object
	 */
	mutex_t *mutex;
};

METHOD(imc_t, set_id, void,
	private_tnc_imc_t *this, TNC_IMCID id)
{
	this->id = id;
}

METHOD(imc_t, get_id, TNC_IMCID,
	private_tnc_imc_t *this)
{
	return this->id;
}

METHOD(imc_t, get_name, char*,
	private_tnc_imc_t *this)
{
	return this->name;
}

METHOD(imc_t, set_message_types, void,
	private_tnc_imc_t *this, TNC_MessageTypeList supported_types,
							 TNC_UInt32 type_count)
{
	char buf[512];
	char *pos = buf;
	int len = sizeof(buf);
	int written;

	/* lock the imc_t instance */
	this->mutex->lock(this->mutex);

	/* Free an existing MessageType list */
	free(this->supported_types);
	this->supported_types = NULL;

	/* Store the new MessageType list */
	this->type_count = type_count;
	if (type_count && supported_types)
	{
		size_t size = type_count * sizeof(TNC_MessageType);
		int i;

		for (i = 0; i < type_count; i++)
		{
			written = snprintf(pos, len, " 0x%08x", supported_types[i]);
			if (written >= len)
			{
				break;
			}
			pos += written;
			len -= written;
		}
		this->supported_types = malloc(size);
		memcpy(this->supported_types, supported_types, size);
	}
	*pos = '\0';
	DBG2(DBG_TNC, "IMC %u supports %u message types:%s",
				  this->id, type_count, buf);

	/* lock the imc_t instance */
	this->mutex->unlock(this->mutex);
}

METHOD(imc_t, type_supported, bool,
	private_tnc_imc_t *this, TNC_MessageType message_type)
{
	TNC_VendorID msg_vid, vid;
	TNC_MessageSubtype msg_subtype, subtype;
	int i;

    msg_vid = (message_type >> 8) & TNC_VENDORID_ANY;
	msg_subtype = message_type & TNC_SUBTYPE_ANY;

	for (i = 0; i < this->type_count; i++)
	{
	    vid = (this->supported_types[i] >> 8) & TNC_VENDORID_ANY;
	    subtype = this->supported_types[i] & TNC_SUBTYPE_ANY;

	    if (this->supported_types[i] == message_type
		|| (subtype == TNC_SUBTYPE_ANY
			&& (msg_vid == vid || vid == TNC_VENDORID_ANY))
		|| (vid == TNC_VENDORID_ANY 
		    && (msg_subtype == subtype || subtype == TNC_SUBTYPE_ANY)))
		{
			return TRUE;
		}
	}
	return FALSE;
}

METHOD(imc_t, destroy, void,
	private_tnc_imc_t *this)
{
	dlclose(this->handle);
	this->mutex->destroy(this->mutex);
	free(this->supported_types);
	free(this->name);
	free(this->path);
	free(this);
}

/**
 * Described in header.
 */
imc_t* tnc_imc_create(char *name, char *path)
{
	private_tnc_imc_t *this;

	INIT(this,
		.public = {
			.set_id = _set_id,
			.get_id = _get_id,
			.get_name = _get_name,
			.set_message_types = _set_message_types,
			.type_supported = _type_supported,
			.destroy = _destroy,
        },
		.name = name,
		.path = path,
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	this->handle = dlopen(path, RTLD_LAZY);
	if (!this->handle)
	{
		DBG1(DBG_TNC, "IMC \"%s\" failed to load: %s", name, dlerror());
		free(this);
		return NULL;
	}

	this->public.initialize = dlsym(this->handle, "TNC_IMC_Initialize");
	if (!this->public.initialize)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMC_Initialize in %s: %s\n",
					   path, dlerror());
		dlclose(this->handle);
		free(this);
		return NULL;
	}
	this->public.notify_connection_change =
						 dlsym(this->handle, "TNC_IMC_NotifyConnectionChange");
    this->public.begin_handshake = dlsym(this->handle, "TNC_IMC_BeginHandshake");
	if (!this->public.begin_handshake)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMC_BeginHandshake in %s: %s\n",
					   path, dlerror());
		dlclose(this->handle);
		free(this);
		return NULL;
	}
    this->public.receive_message =
						dlsym(this->handle, "TNC_IMC_ReceiveMessage");
    this->public.batch_ending =
						dlsym(this->handle, "TNC_IMC_BatchEnding");
    this->public.terminate =
						dlsym(this->handle, "TNC_IMC_Terminate");
    this->public.provide_bind_function =
						dlsym(this->handle, "TNC_IMC_ProvideBindFunction");
    if (!this->public.provide_bind_function)
	{
		DBG1(DBG_TNC, "could not resolve TNC_IMC_ProvideBindFunction in %s: %s\n",
					  path, dlerror());
		dlclose(this->handle);
		free(this);
		return NULL;
	}

	return &this->public;
}
