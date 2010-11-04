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

typedef struct private_tnc_imc_t private_tnc_imc_t;

struct private_tnc_imc_t {

	/**
	 * Public members of imc_t.
	 */
	imc_t public;

	/**
	 * Name of loaded IMC
	 */
	char *name;

	/**
	 * ID of loaded IMC
	 */
	TNC_IMCID id;
};

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

METHOD(imc_t, destroy, void,
	private_tnc_imc_t *this)
{
	free(this->name);
	free(this);
}

/**
 * Described in header.
 */
imc_t* tnc_imc_create(char* name, char *filename, TNC_IMCID id)
{
	private_tnc_imc_t *this;
	void *handle;

	INIT(this,
		.public = {
			.get_id = _get_id,
			.destroy = _destroy,
        },
	);

	handle = dlopen(filename, RTLD_NOW);
	if (handle == NULL)
	{
		DBG1(DBG_TNC, "IMC '%s' failed to load from '%s': %s",
					   name, filename, dlerror());
		free(this->name);
		free(this);
		return NULL;
	}

	/* we do not store or free dlopen() handles, leak_detective requires
	 * the modules to keep loaded until leak report */
 
	this->public.initialize = dlsym(handle, "TNC_IMC_Initialize");
	if (!this->public.initialize)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMC_Initialize in %s: %s\n",
					   filename, dlerror());
		free(this);
		return NULL;
	}
	this->public.notify_connection_change =
						 dlsym(handle, "TNC_IMC_NotifyConnectionChange");
    this->public.begin_handshake = dlsym(handle, "TNC_IMC_BeginHandshake");
	if (!this->public.begin_handshake)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMC_BeginHandshake in %s: %s\n",
					   filename, dlerror());
		free(this);
		return NULL;
	}
    this->public.receive_message = 
						dlsym(handle, "TNC_IMC_ReceiveMessage");
    this->public.batch_ending =
						dlsym(handle, "TNC_IMC_BatchEnding");
    this->public.terminate =
						dlsym(handle, "TNC_IMC_Terminate");
    this->public.provide_bind_function =
						dlsym(handle, "TNC_IMC_ProvideBindFunction");
    if (!this->public.provide_bind_function)
	{
		DBG1(DBG_TNC, "could not resolve TNC_IMC_ProvideBindFunction in %s: %s\n",
					  filename, dlerror());
		free(this);
		return NULL;
	}
	DBG2(DBG_TNC, "IMC '%s' loaded successfully with ID %u", name, id);
	this->name = strdup(name);
	this->id = id;

	return &this->public;
}

