/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup imv imv
 * @{ @ingroup libcharon
 */

#ifndef IMV_H_
#define IMV_H_

#include <tnc/tncifimv.h>

typedef struct imv_t imv_t;

struct imv_t {

	/**
	 * The TNC Server calls this function to initialize the IMV and agree on
	 * the API version number to be used. It also supplies the IMV ID, an IMV
	 * identifier that the IMV must use when calling TNC Server callback functions.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param minVersion		Minimum API version supported 
	 * @param maxVersion		Maximum API version supported by TNCS
	 * @param OutActualVersion	Mutually supported API version number
	 * @result					TNC result code
	 */
	TNC_Result (*initialize)(TNC_IMVID imvID,
							 TNC_Version minVersion,
							 TNC_Version maxVersion,
							 TNC_Version *OutActualVersion);

	/**
	 * The TNC Server calls this function to inform the IMV that the state of
	 * the network connection identified by connectionID has changed to newState.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param connectionID		Network connection ID assigned by TNCS
	 * @param newState			New network connection state
	 * @result					TNC result code
	 */
	TNC_Result (*notify_connection_change)(TNC_IMVID imvID,
										   TNC_ConnectionID connectionID,
										   TNC_ConnectionState newState);

	/**
	 * The TNC Server calls this function at the end of an Integrity Check
	 * Handshake (after all IMC-IMV messages have been delivered) to solicit
	 * recommendations from IMVs that have not yet provided a recommendation.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param connectionID		Network connection ID assigned by TNCS
	 * @result					TNC result code
	 */
	TNC_Result (*solicit_recommendation)(TNC_IMVID imvID,
										 TNC_ConnectionID connectionID);

	/**
	 * The TNC Server calls this function to deliver a message to the IMV.
	 * The message is contained in the buffer referenced by message and contains
	 * the number of octets indicated by messageLength. The type of the message
	 * is indicated by messageType.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param connectionID		Network connection ID assigned by TNCS
	 * @param message			Reference to buffer containing message
	 * @param messageLength		Number of octets in message
	 * @param messageType		Message type of message
	 * @result					TNC result code
	 */
	TNC_Result (*receive_message)(TNC_IMVID imvID,
								  TNC_ConnectionID connectionID,
								  TNC_BufferReference message,
								  TNC_UInt32 messageLength,
								  TNC_MessageType messageType);

	/**
	 * The TNC Server calls this function to notify IMVs that all IMC messages
	 * received in a batch have been delivered and this is the IMV’s last chance
	 * to send a message in the batch of IMV messages currently being collected.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param connectionID		Network connection ID assigned by TNCS
	 * @result					TNC result code
	 */
	TNC_Result (*batch_ending)(TNC_IMVID imvID,
							   TNC_ConnectionID connectionID);

	/**
	 * The TNC Server calls this function to close down the IMV.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @result					TNC result code
	 */
	TNC_Result (*terminate)(TNC_IMVID imvID);

	/**
	 * IMVs implementing the UNIX/Linux Dynamic Linkage platform binding MUST
	 * define this additional function. The TNC Server MUST call the function
	 * immediately after calling TNC_IMV_Initialize to provide a pointer to the
	 * TNCS bind function. The IMV can then use the TNCS bind function to obtain
	 * pointers to any other TNCS functions.
	 *
	 * @param imvID				IMV ID assigned by TNCS
	 * @param bindFunction		Pointer to TNC_TNCS_BindFunction
	 * @result					TNC result code
	 */
	TNC_Result (*provide_bind_function)(TNC_IMVID imvID,
										TNC_TNCS_BindFunctionPointer bindFunction);

	/**
	 * Returns the ID of an imv_t object.
	 *
	 * @result					IMV ID assigned by TNCS
	 */
	TNC_IMVID (*get_id)(imv_t *this);

	/**
	 * Returns the name of an imv_t object.
	 *
	 * @result					name of IMV
	 */
	char* (*get_name)(imv_t *this);

	/**
	 * Destroys an imv_t object.
	 */
	void (*destroy)(imv_t *this);
};

#endif /** IMV_H_ @}*/
