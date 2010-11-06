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
#include <daemon.h>

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

METHOD(imc_t, destroy, void,
	private_tnc_imc_t *this)
{
	free(this->name);
	free(this);
}

/**
 * Described in header.
 */
imc_t* tnc_imc_create(char* name, char *filename)
{
	private_tnc_imc_t *this;
	void *handle;

	INIT(this,
		.public = {
			.set_id = _set_id,
			.get_id = _get_id,
			.get_name = _get_name,
			.destroy = _destroy,
        },
	);

	handle = dlopen(filename, RTLD_NOW);
	if (handle == NULL)
	{
		DBG1(DBG_TNC, "IMC '%s' failed to load from '%s': %s",
					   name, filename, dlerror());
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
	this->name = strdup(name);

	return &this->public;
}

/**
 * Called by the IMC to inform a TNCC about the set of message types the IMC
 * is able to receive
 */
TNC_Result TNC_TNCC_ReportMessageTypes(TNC_IMCID imc_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count)
{
	DBG2(DBG_TNC,"TNCC_ReportMessageTypes %u %u", imc_id, type_count);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMC to ask a TNCC to retry an Integrity Check Handshake
 */
TNC_Result TNC_TNCC_RequestHandshakeRetry(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason)
{
	DBG2(DBG_TNC,"TNCC_RequestHandshakeRetry %u %u", imc_id, connection_id);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMC when an IMC-IMV message is to be sent
 */
TNC_Result TNC_TNCC_SendMessage(TNC_IMCID imc_id,
								TNC_ConnectionID connection_id,
								TNC_BufferReference message,
								TNC_UInt32 message_len,
								TNC_MessageType message_type)
{
	DBG2(DBG_TNC,"TNCC_SendMessage %u %u '%s' %u %0x", imc_id, connection_id,
				  message, message_len, message_type);
	return charon->tnccs->send_message(charon->tnccs, connection_id, message,
									   message_len, message_type);
}

/**
 * Called by the IMC when it needs a function pointer
 */
TNC_Result TNC_TNCC_BindFunction(TNC_IMCID id,
								 char *function_name,
								 void **function_pointer)
{
	if (streq(function_name, "TNC_TNCC_ReportMessageTypes"))
	{
		*function_pointer = (void*)TNC_TNCC_ReportMessageTypes;
	}
    else if (streq(function_name, "TNC_TNCC_RequestHandshakeRetry"))
	{
		*function_pointer = (void*)TNC_TNCC_RequestHandshakeRetry;
	}
    else if (streq(function_name, "TNC_TNCC_SendMessage"))
	{
		*function_pointer = (void*)TNC_TNCC_SendMessage;
	}
    else
	{
		return TNC_RESULT_INVALID_PARAMETER;
	}
    return TNC_RESULT_SUCCESS;
}
