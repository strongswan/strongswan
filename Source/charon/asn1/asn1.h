/**
 * @file asn1.h
 *
 * @brief Definition of asn1_type_t and asn1_rule_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef ASN1_H_
#define ASN1_H_

#include <types.h>

typedef enum asn1_type_t asn1_type_t;

enum asn1_type_t {
	ASN1_END = 0x00,
	ASN1_BOOLEAN = 0x01,
	ASN1_INTEGER = 0x02,
	ASN1_BIT_STRING = 0x03,
	ASN1_OCTET_STRING = 0x04,
	ASN1_NULL = 0x05,
	ASN1_OID = 0x06,
	ASN1_ENUMERATED = 0x0A,
	ASN1_UTF8STRING = 0x0C,
	ASN1_NUMERICSTRING = 0x12,
	ASN1_PRINTABLESTRING = 0x13,
	ASN1_T61STRING = 0x14,
	ASN1_VIDEOTEXSTRING = 0x15,
	ASN1_IA5STRING = 0x16,
	ASN1_UTCTIME = 0x17,
	ASN1_GENERALIZEDTIME = 0x18,
	ASN1_GRAPHICSTRING = 0x19,
	ASN1_VISIBLESTRING = 0x1A,
	ASN1_GENERALSTRING = 0x1B,
	ASN1_UNIVERSALSTRING = 0x1C,
	ASN1_BMPSTRING = 0x1E,
	ASN1_CONSTRUCTED = 0x20,
	ASN1_SEQUENCE = 0x30,
	ASN1_SET = 0x31,
	ASN1_TAG_E_0 = 0xA0,
	ASN1_TAG_E_1 = 0xA1,
	ASN1_TAG_E_2 = 0xA2,
	ASN1_TAG_E_3 = 0xA3,
	ASN1_TAG_E_4 = 0xA4,
	ASN1_TAG_E_5 = 0xA5,
	ASN1_TAG_E_6 = 0xA6,
	ASN1_TAG_E_7 = 0xA7,
	ASN1_TAG_I_1 = 0x81,
	ASN1_TAG_I_2 = 0x82,
	ASN1_TAG_I_3 = 0x83,
	ASN1_TAG_I_4 = 0x84,
	ASN1_TAG_I_5 = 0x85,
	ASN1_TAG_I_6 = 0x86,
	ASN1_TAG_I_7 = 0x87,
};

extern mapping_t asn1_type_m[];

typedef enum asn1_flag_t asn1_flag_t;

enum asn1_flag_t {
	ASN1_OPTIONAL = 0x01,
	ASN1_DEFAULT = 0x02,
	ASN1_MPZ = 0x04,
	ASN1_OF = 0x08,
};

extern mapping_t asn1_flag_m[];


typedef struct asn1_rule_t asn1_rule_t;

struct asn1_rule_t {
	/** 
	 * ASN1 type 
	 */
	asn1_type_t type;
	/** 
	 * implicit or explicit tag, if any 
	 */
	asn1_flag_t flags;
	/** 
	 * offset of data in structure 
	 */
	u_int data_offset;
// 	union {
		/** 
		 * offset to a boolean, which says if optional 
		 * data is available at data_offset. Used if
		 * flags & ASN1_OPTIONAL.
		 */
// 		u_int available_offset;
		/**
		 * default value, used if flags & ASN1_DEFAULT
		 */
		u_int default_value;
// 	};
};


#endif /* ASN1_H_ */
