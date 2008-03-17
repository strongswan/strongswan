/*
 * Copyright (C) 2008 Martin Willi
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

#include "builder.h"

ENUM(builder_part_names, BUILD_BLOB_ASN1_DER, BUILD_END,
	"BUILD_BLOB_ASN1_DER",
	"BUILD_KEY_SIZE",
	"BUILD_SIGNING_KEY",
	"BUILD_SIGNING_CERT",
	"BUILD_PUBLIC_KEY",
	"BUILD_SUBJECT",
	"BUILD_SUBJECT_ALTNAME",
	"BUILD_ISSUER",
	"BUILD_ISSUER_ALTNAME",
	"BUILD_CA_CERT",
	"BUILD_CERT",
	"BUILD_X509_FLAG",
	"BUILD_END",
);
