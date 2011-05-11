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

#include <debug.h>
#include <daemon.h>

#define TNC_IMCID_ANY	0xffff

/**
 * Called by the IMV to inform a TNCS about the set of message types the IMV
 * is able to receive
 */
TNC_Result TNC_TNCS_ReportMessageTypes(TNC_IMVID imv_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count)
{
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring ReportMessageTypes() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->imvs->set_message_types(charon->imvs, imv_id,
										   supported_types, type_count);
}

/**
 * Called by the IMV to ask a TNCS to retry an Integrity Check Handshake
 */
TNC_Result TNC_TNCS_RequestHandshakeRetry(TNC_IMVID imv_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason)
{
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring RequestHandshakeRetry() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->tnccs->request_handshake_retry(charon->tnccs, FALSE, imv_id,
												  connection_id, reason);
}

/**
 * Called by the IMV when an IMV-IMC message is to be sent
 */
TNC_Result TNC_TNCS_SendMessage(TNC_IMVID imv_id,
								TNC_ConnectionID connection_id,
								TNC_BufferReference msg,
								TNC_UInt32 msg_len,
								TNC_MessageType msg_type)
{
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring SendMessage() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->tnccs->send_message(charon->tnccs, TNC_IMCID_ANY, imv_id,
									   connection_id, msg, msg_len, msg_type);
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
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring ProvideRecommendation() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->tnccs->provide_recommendation(charon->tnccs, imv_id,
							connection_id, recommendation, evaluation);
}

/**
 * Called by the IMV to get the value of an attribute associated with a
 * connection or with the TNCS as a whole.
 */
TNC_Result TNC_TNCS_GetAttribute(TNC_IMVID imv_id,
								 TNC_ConnectionID connection_id,
								 TNC_AttributeID attribute_id,
								 TNC_UInt32 buffer_len,
								 TNC_BufferReference buffer,
								 TNC_UInt32 *out_value_len)
{
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring GetAttribute() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->tnccs->get_attribute(charon->tnccs, imv_id, connection_id,
							attribute_id, buffer_len, buffer, out_value_len);
}

/**
 * Called by the IMV to set the value of an attribute associated with a
 * connection or with the TNCS as a whole.
 */
TNC_Result TNC_TNCS_SetAttribute(TNC_IMVID imv_id,
								 TNC_ConnectionID connection_id,
								 TNC_AttributeID attribute_id,
								 TNC_UInt32 buffer_len,
								 TNC_BufferReference buffer)
{
	if (!charon->imvs->is_registered(charon->imvs, imv_id))
	{
		DBG1(DBG_TNC, "ignoring SetAttribute() from unregistered IMV %u",
					   imv_id);
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return charon->tnccs->set_attribute(charon->tnccs, imv_id, connection_id,
										attribute_id, buffer_len, buffer);
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
	else if (streq(function_name, "TNC_TNCS_GetAttribute"))
	{
		*function_pointer = (void*)TNC_TNCS_GetAttribute;
	}
	else if (streq(function_name, "TNC_TNCS_SetAttribute"))
	{
		*function_pointer = (void*)TNC_TNCS_SetAttribute;
	}
	else
	{
		return TNC_RESULT_INVALID_PARAMETER;
	}
	return TNC_RESULT_SUCCESS;
}
