/*
 * Copyright (C) 2007 Martin Willi
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

#include "public_key.h"

ENUM(key_type_names, KEY_RSA, KEY_ECDSA,
	"RSA",
	"ECDSA"
);

ENUM(signature_scheme_names, SIGN_DEFAULT, SIGN_ECDSA_521,
	"DEFAULT",
	"RSA_EMSA_PKCS1_MD5",
	"RSA_EMSA_PKCS1_SHA1",
	"RSA_EMSA_PKCS1_SHA256",
	"RSA_EMSA_PKCS1_SHA384",
	"RSA_EMSA_PKCS1_SHA512",
	"ECDSA_WITH_SHA1",
	"ECDSA-256",
	"ECDSA-384",
	"ECDSA-521",
);

