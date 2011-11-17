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

ENUM(encoding_type_names, U_INT_4, IKE_SPI,
	"U_INT_4",
	"U_INT_8",
	"U_INT_16",
	"U_INT_32",
	"RESERVED_BIT",
	"RESERVED_BYTE",
	"FLAG",
	"PAYLOAD_LENGTH",
	"HEADER_LENGTH",
	"SPI_SIZE",
	"SPI",
	"PROPOSALS",
	"PROPOSALS_V1",
	"TRANSFORMS",
	"TRANSFORMS_V1",
	"TRANSFORM_ATTRIBUTES",
	"TRANSFORM_ATTRIBUTES_V1",
	"CONFIGURATION_ATTRIBUTES",
	"ATTRIBUTE_FORMAT",
	"ATTRIBUTE_TYPE",
	"ATTRIBUTE_LENGTH_OR_VALUE",
	"CONFIGURATION_ATTRIBUTE_LENGTH",
	"ATTRIBUTE_VALUE",
	"TRAFFIC_SELECTORS",
	"TS_TYPE",
	"ADDRESS",
	"CHUNK_DATA",
	"IKE_SPI",
);
