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

#include <types.h>
#include <definitions.h>


typedef enum encoding_type_t encoding_type_t;

/**
 * @brief All different kinds of encoding types. 
 *
 * Each field of an IKEv2-Message (in header or payload) 
 * which has to be parsed or generated differently has its own
 * type defined here.
 */
enum encoding_type_t{
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
	 * Representating a length field of a payload
	 * 
 	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 16 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 16 bit forward afterwards.
	 */
	PAYLOAD_LENGTH,
	/**
	 * Representating a length field of a header
	 * 
 	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 32 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 32 bit forward afterwards.
	 */
	HEADER_LENGTH,
	/**
	 * Representating a spi size field
	 * 
 	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
	 * The current write position is moved 8 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 8 bit forward afterwards.
	 */
	SPI_SIZE,
	/**
	 * Representating a spi field
	 * 
 	 * When generating the content of the chunkt pointing to 
 	 * is written.
	 * 
	 * When parsing SPI_SIZE bytes are read and written into the chunk pointing to.
	 */
	SPI,
	/**
	 * Representating a Key Exchange Data field
	 * 
 	 * When generating the content of the chunkt pointing to 
 	 * is written.
	 * 
	 * When parsing (Payload Length - 8) bytes are read and written into the chunk pointing to.
	 */
	KEY_EXCHANGE_DATA,
	/**
	 * Representating a Notification field
	 * 
 	 * When generating the content of the chunkt pointing to 
 	 * is written.
	 * 
	 * When parsing (Payload Length - spi size - 8) bytes are read and written into the chunk pointing to.
	 */
	NOTIFICATION_DATA,
	/**
	 * Representating one or more proposal substructures
	 * 
	 * The offset points to a linked_list_t pointer.
	 * 
	 * When generating the proposal_substructure_t objects are stored 
	 * in the pointed linked_list.
	 * 
	 * When parsing the parsed proposal_substructure_t objects have 
	 * to be stored in the pointed linked_list.
	 */	
	PROPOSALS,
	/**
	 * Representating one or more transform substructures
	 * 
	 * The offset points to a linked_list_t pointer.
	 * 
	 * When generating the transform_substructure_t objects are stored 
	 * in the pointed linked_list.
	 * 
	 * When parsing the parsed transform_substructure_t objects have 
	 * to be stored in the pointed linked_list.
	 */	
	TRANSFORMS,
	/**
	 * Representating one or more Attributes of a transform substructure
	 * 
	 * The offset points to a linked_list_t pointer.
	 * 
	 * When generating the transform_attribute_t objects are stored 
	 * in the pointed linked_list.
	 * 
	 * When parsing the parsed transform_attribute_t objects have 
	 * to be stored in the pointed linked_list.
	 */	
	TRANSFORM_ATTRIBUTES,
	/**
	 * Representing a 1 Bit flag specifying the format of a transform attribute.
	 * 
	 * When generation, the next bit is set to 1 if the associated value 
	 * in the data struct is TRUE, 0 otherwise. The current write position 
	 * is moved 1 bit forward afterwards.
	 *
	 * When parsing, the next bit is read and stored in the associated data 
	 * struct. 0 means FALSE, 1 means TRUE, The current read pointer 
	 * is moved 1 bit forward afterwards.
	 */
	ATTRIBUTE_FORMAT,
	/**
	 * Representing a 15 Bit unsigned int value used as attribute type 
	 * in an attribute transform
	 * 
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
 	 * The current write position is moved 15 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 15 bit forward afterwards.
	 */
	ATTRIBUTE_TYPE,

	/**
	 * Depending on the field of type ATTRIBUTE_FORMAT
	 * this field contains the length or the value of an transform attribute.
	 * Its stored in a 16 unsigned integer field
	 * 
	 * When generating it must be changed from host to network order.
	 * The value is read from the associated data struct.
 	 * The current write position is moved 16 bit forward afterwards.
	 * 
	 * When parsing it must be changed from network to host order.
	 * The value is written to the associated data struct.
	 * The current read pointer is moved 16 bit forward afterwards.
	 */
	ATTRIBUTE_LENGTH_OR_VALUE,

	/*	
	 * Depending on the field of type ATTRIBUTE_FORMAT
	 * this field is available or missing and so parsed/generated 
	 * or not parsed/not generated
	 * 
 	 * When generating the content of the chunkt pointing to 
 	 * is written.
	 * 
	 * When parsing SPI_SIZE bytes are read and written into the chunk pointing to.
	 */
	ATTRIBUTE_VALUE,

	/**
	 * Representating a Nonce Data field
	 * 
 	 * When generating the content of the chunkt pointing to 
 	 * is written.
	 * 
	 * When parsing (Payload Length - 4) bytes are read and written into the chunk pointing to.
	 */
	NONCE_DATA,

	/**
	 * Representating an IKE_SPI field in an IKEv2 Header
	 * 
 	 * When generating the value of the u_int64_t pointing to 
 	 * is written (host and networ order is not changed).
	 * 
	 * When parsing 8 bytes are read and written into the u_int64_t pointing to.
	 */
	IKE_SPI
};

/**
 * mappings to map encoding_type_t's to strings
 */
extern mapping_t encoding_type_m[];

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





#endif /*ENCODINGS_H_*/
