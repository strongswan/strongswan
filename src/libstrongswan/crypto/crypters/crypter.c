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

#include "crypter.h"

ENUM_BEGIN(encryption_algorithm_names, ENCR_UNDEFINED, ENCR_UNDEFINED,
	"UNDEFINED");
ENUM_NEXT(encryption_algorithm_names, ENCR_DES_IV64, ENCR_DES_IV32, ENCR_UNDEFINED,
	"DES_IV64",
	"DES",
	"3DES",
	"RC5",
	"IDEA",
	"CAST",
	"BLOWFISH",
	"3IDEA",
	"DES_IV32");
ENUM_NEXT(encryption_algorithm_names, ENCR_NULL, ENCR_AES_CCM_ICV16, ENCR_DES_IV32,
	"NULL",
	"AES_CBC",
	"AES_CTR",
	"AES_CCM_8",
	"AES_CCM_12",
	"AES_CCM_16");
ENUM_NEXT(encryption_algorithm_names, ENCR_AES_GCM_ICV8, ENCR_NULL_AUTH_AES_GMAC, ENCR_AES_CCM_ICV16,
	"AES_GCM_8",
	"AES_GCM_12",
	"AES_GCM_16",
	"NULL_AES_GMAC");
ENUM_NEXT(encryption_algorithm_names, ENCR_CAMELLIA_CBC, ENCR_CAMELLIA_CCM_ICV16, ENCR_NULL_AUTH_AES_GMAC,
	"CAMELLIA_CBC",
	"CAMELLIA_CTR",
	"CAMELLIA_CCM_ICV8",
	"CAMELLIA_CCM_ICV12",
	"CAMELLIA_CCM_ICV16");
ENUM_NEXT(encryption_algorithm_names, ENCR_DES_ECB, ENCR_DES_ECB, ENCR_CAMELLIA_CCM_ICV16,
	"DES_ECB");
ENUM_END(encryption_algorithm_names, ENCR_DES_ECB);

