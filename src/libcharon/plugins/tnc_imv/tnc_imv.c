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

#include "tnc_imv.h"

#include <dlfcn.h>

#include <debug.h>
#include <library.h>

typedef struct private_tnc_imv_t private_tnc_imv_t;

struct private_tnc_imv_t {

	/**
	 * Public members of imv_t.
	 */
	imv_t public;

	/**
	 * Name of loaded IMV
	 */
	char *name;

	/**
	 * ID of loaded IMV
	 */
	TNC_IMVID id;
};

METHOD(imv_t, set_id, void,
	private_tnc_imv_t *this, TNC_IMVID id)
{
	this->id = id;
}

METHOD(imv_t, get_id, TNC_IMVID,
	private_tnc_imv_t *this)
{
	return this->id;
}

METHOD(imv_t, get_name, char*,
	private_tnc_imv_t *this)
{
	return this->name;
}

METHOD(imv_t, destroy, void,
	private_tnc_imv_t *this)
{
	free(this->name);
	free(this);
}

/**
 * Described in header.
 */
imv_t* tnc_imv_create(char *name, char *filename)
{
	private_tnc_imv_t *this;
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
		DBG1(DBG_TNC, "IMV '%s' failed to load from '%s': %s",
					   name, filename, dlerror());
		free(this);
		return NULL;
	}

	/* we do not store or free dlopen() handles, leak_detective requires
	 * the modules to keep loaded until leak report */

	this->public.initialize = dlsym(handle, "TNC_IMV_Initialize");
	if (!this->public.initialize)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMV_Initialize in %s: %s\n",
					   filename, dlerror());
		free(this);
		return NULL;
	}
	this->public.notify_connection_change =
						dlsym(handle, "TNC_IMV_NotifyConnectionChange");
    this->public.solicit_recommendation =
						dlsym(handle, "TNC_IMV_SolicitRecommendation");
	if (!this->public.solicit_recommendation)
    {
		DBG1(DBG_TNC, "could not resolve TNC_IMV_SolicitRecommendation in %s: %s\n",
					   filename, dlerror());
		free(this);
		return NULL;
	}
    this->public.receive_message =
						dlsym(handle, "TNC_IMV_ReceiveMessage");
    this->public.batch_ending =
						dlsym(handle, "TNC_IMV_BatchEnding");
    this->public.terminate =
						dlsym(handle, "TNC_IMV_Terminate");
    this->public.provide_bind_function =
						dlsym(handle, "TNC_IMV_ProvideBindFunction");
    if (!this->public.provide_bind_function)
	{
		DBG1(DBG_TNC, "could not resolve TNC_IMV_ProvideBindFunction in %s: %s\n",
					  filename, dlerror());
		free(this);
		return NULL;
	}
	this->name = strdup(name);

	return &this->public;
}

/**
 * Called by the IMV to inform a TNCS about the set of message types the IMV
 * is able to receive
 */
TNC_Result TNC_TNCS_ReportMessageTypes(TNC_IMVID imv_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count)
{
	DBG2(DBG_TNC,"TNCS_ReportMessageTypes %u %u", imv_id, type_count);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMV to ask a TNCS to retry an Integrity Check Handshake
 */
TNC_Result TNC_TNCS_RequestHandshakeRetry(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason)
{
	DBG2(DBG_TNC,"TNCS_RequestHandshakeRetry %u %u", imv_id, connection_id);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMV when an IMV-IMC message is to be sent
 */
TNC_Result TNC_TNCS_SendMessage(TNC_IMVID imv_id,
								TNC_ConnectionID connection_id,
								TNC_BufferReference message,
								TNC_UInt32 message_len,
								TNC_MessageType message_type)
{
	DBG2(DBG_TNC,"TNCS_SendMessage %u %u '%s' %u %0x", imv_id, connection_id,
				  message, message_len, message_type);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMV to deliver its IMV Action Recommendation and IMV Evaluation
 * Result to the TNCS
 */
TNC_Result TNC_TNCS_ProvideRecommendation(TNC_IMVID imv_id,
								TNC_ConnectionID connection_id,
								TNC_IMV_Action_Recommendation recommendation,
								TNC_IMV_Evaluation_Result evaluation)
{
	DBG2(DBG_TNC,"TNCS_ProvideRecommendation %u %u", imv_id, connection_id);
	return TNC_RESULT_SUCCESS;
}

/**
 * Called by the IMV when it needs a function pointer
 */
TNC_Result TNC_TNCS_BindFunction(TNC_IMVID id,
								 char *function_name,
								 void **function_pointer)
{
	if (streq(function_name, "TNC_TNCS_ReportMessageTypes"))
	{
		*function_pointer = (void*)TNC_TNCS_ReportMessageTypes;
	}
    else if (streq(function_name, "TNC_TNCS_RequestHandshakeRetry"))
	{
		*function_pointer = (void*)TNC_TNCS_RequestHandshakeRetry;
	}
    else if (streq(function_name, "TNC_TNCS_SendMessage"))
	{
		*function_pointer = (void*)TNC_TNCS_SendMessage;
	}
    else if (streq(function_name, "TNC_TNCS_ProvideRecommendation"))
	{
		*function_pointer = (void*)TNC_TNCS_ProvideRecommendation;
	}
    else
	{
		return TNC_RESULT_INVALID_PARAMETER;
	}
    return TNC_RESULT_SUCCESS;
}
