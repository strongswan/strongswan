/**
 * @file asn1.c
 *
 * @brief String mappings for asn1.h
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

#include "asn1.h"

mapping_t asn1_type_m[] = {
	{ASN1_END, "ASN1_END"},
	{ASN1_BOOLEAN, "ASN1_BOOLEAN"},
	{ASN1_INTEGER, "ASN1_INTEGER"},
	{ASN1_BITSTRING, "ASN1_BITSTRING"},
	{ASN1_OCTETSTRING, "ASN1_OCTETSTRING"},
	{ASN1_NULL, "ASN1_NULL"},
	{ASN1_OID, "ASN1_OID"},
	{ASN1_ENUMERATED, "ASN1_ENUMERATED"},
	{ASN1_UTF8STRING, "ASN1_UTF8STRING"},
	{ASN1_NUMERICSTRING, "ASN1_NUMERICSTRING"},
	{ASN1_PRINTABLESTRING, "ASN1_PRINTABLESTRING"},
	{ASN1_T61STRING, "ASN1_T61STRING"},
	{ASN1_VIDEOTEXSTRING, "ASN1_VIDEOTEXSTRING"},
	{ASN1_IA5STRING, "ASN1_IA5STRING"},
	{ASN1_UTCTIME, "ASN1_UTCTIME"},
	{ASN1_GENERALIZEDTIME, "ASN1_GENERALIZEDTIME"},
	{ASN1_GRAPHICSTRING, "ASN1_GRAPHICSTRING"},
	{ASN1_VISIBLESTRING, "ASN1_VISIBLESTRING"},
	{ASN1_GENERALSTRING, "ASN1_GENERALSTRING"},
	{ASN1_UNIVERSALSTRING, "ASN1_UNIVERSALSTRING"},
	{ASN1_BMPSTRING, "ASN1_BMPSTRING"},
	{ASN1_CONSTRUCTED, "ASN1_CONSTRUCTED"},
	{ASN1_SEQUENCE, "ASN1_SEQUENCE"},
	{ASN1_SET, "ASN1_SET"},
	{ASN1_TAG_E_0, "ASN1_TAG_E_0"},
	{ASN1_TAG_E_1, "ASN1_TAG_E_1"},
	{ASN1_TAG_E_2, "ASN1_TAG_E_2"},
	{ASN1_TAG_E_3, "ASN1_TAG_E_3"},
	{ASN1_TAG_E_4, "ASN1_TAG_E_4"},
	{ASN1_TAG_E_5, "ASN1_TAG_E_5"},
	{ASN1_TAG_E_6, "ASN1_TAG_E_6"},
	{ASN1_TAG_E_7, "ASN1_TAG_E_7"},
	{ASN1_TAG_I_0, "ASN1_TAG_I_0"},
	{ASN1_TAG_I_1, "ASN1_TAG_I_1"},
	{ASN1_TAG_I_2, "ASN1_TAG_I_2"},
	{ASN1_TAG_I_3, "ASN1_TAG_I_3"},
	{ASN1_TAG_I_4, "ASN1_TAG_I_4"},
	{ASN1_TAG_I_5, "ASN1_TAG_I_5"},
	{ASN1_TAG_I_6, "ASN1_TAG_I_6"},
	{ASN1_TAG_I_7, "ASN1_TAG_I_7"},
	{ASN1_CHOICE, "ASN1_CHOICE"},
};

mapping_t asn1_flag_m[] = {
	{ASN1_OPTIONAL, "ASN1_OPTIONAL"},
	{ASN1_DEFAULT, "ASN1_DEFAULT"},
	{ASN1_MPZ, "ASN1_MPZ"},
	{ASN1_OF, "ASN1_OF"},
};
