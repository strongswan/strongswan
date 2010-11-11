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

#include <debug.h>
#include <daemon.h>

/**
 * Called by the IMC to inform a TNCC about the set of message types the IMC
 * is able to receive
 */
TNC_Result TNC_TNCC_ReportMessageTypes(TNC_IMCID imc_id,
									   TNC_MessageTypeList supported_types,
									   TNC_UInt32 type_count)
{
	return charon->imcs->set_message_types(charon->imcs, imc_id,
										   supported_types, type_count);
}

/**
 * Called by the IMC to ask a TNCC to retry an Integrity Check Handshake
 */
TNC_Result TNC_TNCC_RequestHandshakeRetry(TNC_IMCID imc_id,
										  TNC_ConnectionID connection_id,
										  TNC_RetryReason reason)
{
	DBG2(DBG_TNC,"TNCC_RequestHandshakeRetry not supported yet");
	return TNC_RESULT_CANT_RESPOND;
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
