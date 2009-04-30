/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


#include "encodings.h"

ENUM(encoding_type_names, U_INT_4, ENCRYPTED_DATA,
	"U_INT_4",
	"U_INT_8",
	"U_INT_16",
	"U_INT_32",
	"U_INT_64",
	"RESERVED_BIT",
	"RESERVED_BYTE",
	"FLAG",
	"PAYLOAD_LENGTH",
	"HEADER_LENGTH",
	"SPI_SIZE",
	"SPI",
	"KEY_EXCHANGE_DATA",
	"NOTIFICATION_DATA",
	"PROPOSALS",
	"TRANSFORMS",
	"TRANSFORM_ATTRIBUTES",
	"CONFIGURATION_ATTRIBUTES",
	"CONFIGURATION_ATTRIBUTE_VALUE",
	"ATTRIBUTE_FORMAT",
	"ATTRIBUTE_TYPE",
	"ATTRIBUTE_LENGTH_OR_VALUE",
	"CONFIGURATION_ATTRIBUTE_LENGTH",
	"ATTRIBUTE_VALUE",
	"TRAFFIC_SELECTORS",
	"TS_TYPE",
	"ADDRESS",
	"NONCE_DATA",
	"ID_DATA",
	"AUTH_DATA",
	"CERT_DATA",
	"CERTREQ_DATA",
	"EAP_DATA",
	"SPIS",
	"VID_DATA",
	"UNKNOWN_DATA",
	"IKE_SPI",
	"ENCRYPTED_DATA",
);
