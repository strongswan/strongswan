/**
 * @file encodings.h
 * 
 * @brief Type definitions for parser and generator, 
 * 		  also payload types are defined here.
 * 
 * Header is parsed like a payload and gets its one payload_id 
 * from PRIVATE USE space. Also the substructures 
 * of specific payload types get their own payload_id 
 * from PRIVATE_USE space. See RFC for mor informations.
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

#ifndef ENCODINGS_H_
#define ENCODINGS_H_

#include "../types.h"
#include "../definitions.h"


/**
 * @brief All different kinds of encoding types. 
 *
 * Each field of an IKEv2-Message (in header or payload) 
 * which has to be parsed or generated differently has its own
 * type defined here.
 */
typedef enum encoding_type_e encoding_type_t;

enum encoding_type_e{
	/**
	 * Representing a 4 Bit unsigned int value
	 * 
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 4 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 4 bit forward afterwards.
	 */
	U_INT_4,
	/**
	 * Representing a 8 Bit unsigned int value
	 * 
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 8 bit forward afterwards.
	 *  
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 8 bit forward afterwards.
	 */
	U_INT_8,
	/**
	 * Representing a 16 Bit unsigned int value
	 * 
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
 	 * The current write position is moved 16 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 16 bit forward afterwards.
	 */
	U_INT_16,
	/**
	 * Representing a 32 Bit unsigned int value
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 32 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 32 bit forward afterwards.
	 */

	U_INT_32,
	/**
	 * Representing a 64 Bit unsigned int value
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 64 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 64 bit forward afterwards.
	 */
	U_INT_64,
	/**
	 * @brief represents a RESERVED_BIT used in FLAG-Bytes
	 * 
	 * When generating, the next bit is set to zero and the current write 
	 * position is moved one bit forward.
	 * No value is read from the associated data struct.
	 * The current write position is moved 1 bit forward afterwards.
	 * 
	 * When parsing, the current read pointer is moved one bit forward.
	 * No value is written to the associated data struct.
	 * The current read pointer is moved 1 bit forward afterwards.
	 */
	RESERVED_BIT,
	/**
	 * @brief represents a RESERVED_BYTE
	 * 
	 * When generating, the next byte is set to zero and the current write 
	 * position is moved one byte forward.
	 * No value is read from the associated data struct.
	 * The current write position is moved 1 byte forward afterwards.
	 * 
	 * When parsing, the current read pointer is moved one byte forward.
	 * No value is written to the associated data struct.
	 * The current read pointer is moved 1 byte forward afterwards.
	 */
	RESERVED_BYTE,
	/**
	 * Representing a 1 Bit flag.
	 * 
	 * When generation, the next bit is set to 1 if the associated value 
	 * in the data struct is TRUE, 0 otherwise. The current write position 
	 * is moved 1 bit forward afterwards.
	 *
	 * When parsing, the next bit is read and stored in the associated data 
	 * struct. 0 means FALSE, 1 means TRUE, The current read pointer 
	 * is moved 1 bit forward afterwards
	 */
	FLAG,
	/**
	 * Representating a length field
	 * 
 	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 32 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 32 bit forward afterwards.
	 */
	LENGTH,
	/**
	 * Representating a spi size field
	 * 
 	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 32 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 32 bit forward afterwards.
	 */
	SPI_SIZE
};

/**
 * An encoding rule is a mapping of a specific encoding type to 
 * a location in the data struct where the current field is stored to
 * or read from.
 * 
 * For examples see directory encodings/.
 * 
 * This rules are used by parser and generator.
 */
typedef struct encoding_rule_s encoding_rule_t;

struct encoding_rule_s{
	/**
	 * Encoding type
	 */
	encoding_type_t type;
	/**
	 * Offset in the data struct
	 * 
	 * When parsing, data are written to this offset of the 
	 * data struct.
	 * 
	 * When generating, data are read from this offset in the 
	 * data struct.
	 */
	u_int32_t offset;
};


/**
 * Payload-Types of a IKEv2-Message
 * 
 * 
 * Header and substructures are also defined as 
 * payload types with values from PRIVATE USE space.
 */
typedef enum payload_type_e payload_type_t;

enum payload_type_e{

	/**
	 * NO_PAYLOAD
	 */
	 NO_PAYLOAD = 0,
	
	/**
	 * SA
	 */
	SECURITY_ASSOCIATION = 33,
	/**
	 * KE
	 */
	KEY_EXCHANGE = 34,
	/**
	 * IDi
	 */
	ID_INITIATOR = 35,
	/**
	 * IDr
	 */
	ID_RESPONDER = 36,
	/**
	 * CERT
	 */
	CERTIFICATE = 37,
	/**
	 * CERTREQ
	 */
	CERTIFICATE_REQUEST = 38,
	/**
	 * AUTH
	 */
	AUTHENTICATION = 39,
	/**
	 * Ni, Nr
	 */
	NONCE = 40,
	/**
	 * N
	 */
	NOTIFY = 41,
	/**
	 * D
	 */
	DELETE = 42,
	/**
	 * V
	 */
	VENDOR_ID = 43,
	/**
	 * TSi
	 */
	TRAFFIC_SELECTOR_INITIATOR = 44,
	/**
	 * TSr
	 */
	TRAFFIC_SELECTOR_RESPONDER = 45,
	/**
	 * E
	 */
	ENCRYPTED = 46,
	/**
	 * CP
	 */
	CONFIGURATION = 47,
	/**
	 * EAP
	 */
	EXTENSIBLE_AUTHENTICATION = 48,
	
	/**
	 * Header has value 140 of PRIVATE USE space
	 * 
	 * This payload type is not send over wire and just 
	 * used internally to handle IKEv2-Header like a payload.
	 */
	HEADER = 140
};


/*
 * build string mapping array for payload_type_t
 */
extern mapping_t payload_type_t_mappings[];

/**
 * Information of a specific payload are stored in this struct
 * 
 * The following informations are needed for each payload
 * - payload type 
 * - length of its associated data struct in bytes
 * - encoding rules array
 * - encoding rules count
 */
typedef struct payload_info_s payload_info_t;

struct payload_info_s{
	/**
	 * Type of payload 
	 */
	payload_type_t payload_type;
	/**
	 * Length of associated data struct in bytes
	 */
	size_t data_struct_length;
	
	/**
	 * Pointer to the encoding rules array
	 */
	encoding_rule_t *ecoding_rules;
	
	/**
	 * Number of encoding rules for the specific payload_type
	 */
	size_t encoding_rules_count;
};

#endif /*ENCODINGS_H_*/
