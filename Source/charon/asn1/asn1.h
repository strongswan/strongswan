/**
 * @file asn1.h
 *
 * @brief Definition of asn1_rule_t and other ASN1 stuff.
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

/**
 * @brief Real and some special ASN1 types.
 * 
 * @ingroup asn1
 */
enum asn1_type_t {
	/**
	 * End of a sequence, set, choice
	 */
	ASN1_END = 0x00,
	ASN1_BOOLEAN = 0x01,
	ASN1_INTEGER = 0x02,
	ASN1_BITSTRING = 0x03,
	ASN1_OCTETSTRING = 0x04,
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
	/**
	 * EXCPLICIT tags 
	 */
	ASN1_TAG_E_0 = 0xA0,
	ASN1_TAG_E_1 = 0xA1,
	ASN1_TAG_E_2 = 0xA2,
	ASN1_TAG_E_3 = 0xA3,
	ASN1_TAG_E_4 = 0xA4,
	ASN1_TAG_E_5 = 0xA5,
	ASN1_TAG_E_6 = 0xA6,
	ASN1_TAG_E_7 = 0xA7,
	/**
	 * IMPLICIT tags 
	 */
	ASN1_TAG_I_0 = 0x80,
	ASN1_TAG_I_1 = 0x81,
	ASN1_TAG_I_2 = 0x82,
	ASN1_TAG_I_3 = 0x83,
	ASN1_TAG_I_4 = 0x84,
	ASN1_TAG_I_5 = 0x85,
	ASN1_TAG_I_6 = 0x86,
	ASN1_TAG_I_7 = 0x87,
	/**
	 * Begin of a choice
	 */
	ASN1_CHOICE = 0xFE,
	/**
	 * ANY type
	 */
	ASN1_ANY = 0xFF,
};

/**
 * String mappings for asn1_type_t
 */
extern mapping_t asn1_type_m[];


typedef enum asn1_flag_t asn1_flag_t;

/**
 * @brief Flags used to build ASN1 rules.
 * 
 * @ingroup asn1
 */
enum asn1_flag_t {
	/**
	 * Field is optional
	 */
	ASN1_OPTIONAL = 0x01,
	/**
	 * Field has a default value and is therefore optional
	 */
	ASN1_DEFAULT = 0x02,
	/**
	 * Convert this INTEGER to an mpz_t
	 */
	ASN1_MPZ = 0x04,
	/**
	 * SEQUENCE or SET OF
	 */
	ASN1_OF = 0x08,
	/**
	 * Parse this Sequence in a RAW chunk too.
	 * Used for crypto calculations...
	 */
	ASN1_RAW = 0x10,
};

/**
 * String mappings for asn1_flag_t
 */
extern mapping_t asn1_flag_m[];


typedef struct asn1_rule_t asn1_rule_t;

/**
 * @brief Single rule of a complet ruleset.
 * 
 * This rule containing a type, flags and additional
 * data allow modellation of complex ASN1 structures and
 * allow their en- and decoding...
 * 
 * @ingroup asn1
 */
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
	/**
	 * offset to a boolean, which says if optional 
	 * data is available at data_offset. Used if
	 * flags & ASN1_OPTIONAL.
	 * default value, used if flags & ASN1_DEFAULT
	 */
	u_int additional;
};


#endif /* ASN1_H_ */
