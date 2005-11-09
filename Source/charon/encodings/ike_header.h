/**
 * @file ike_header.h
 * 
 * @brief Declaration of the data struct ike_header_t. 
 * 
 * The data of a parsed header are stored in a struct of this type.
 * 
 */

/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
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

#ifndef IKE_HEADER_H_
#define IKE_HEADER_H_

#include <freeswan.h>
#include <pluto/constants.h>
#include <pluto/defs.h>

/**
 * Data structure to hold the data of an IKEv2-Header
 * 
 * The header format of an IKEv2-Message is compatible to the 
 * ISAKMP-Header format to allow implementations supporting 
 * both versions of the IKE-protocol.
 * 
 */
typedef struct ike_header_s ike_header_t;

struct ike_header_s{
	/**
	 * SPI of the initiator
	 */
	u_int64_t initiator_spi;
	/**
	 * SPI of the responder
	 */
	u_int64_t responder_spi;
	/**
	 * next payload type
	 */
	u_int8_t  next_payload;
	/**
	 * IKE major version
	 */
	u_int8_t  maj_version;

	/**
	 * IKE minor version
	 */	
	u_int8_t  min_version;

	/**
	 * Exchange type 
	 */	
	u_int8_t  exchange_type;
	
	/**
	 * Flags of the Message
	 * 
	 */
	struct { 
		/**
		 * Sender is initiator of the associated IKE_SA_INIT-Exchange
		 */
		bool initiator;
		/**
		 * is protocol supporting higher version?
		 */
		bool version;
		/**
		 * TRUE, if this is a response, FALSE if its a Request
		 */
		bool response;
	} flags;
	/**
	 * Associated Message-ID
	 */
	u_int32_t message_id;
	/**
	 * Length of the whole IKEv2-Message (header and all payloads)
	 */
	u_int32_t length;
};

#endif /*IKE_HEADER_H_*/
