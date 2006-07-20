/**
 * @file signer.c
 * 
 * @brief Implementation of generic signer_t constructor.
 * 
 */

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

#include "signer.h"

#include <crypto/signers/hmac_signer.h>

/** 
 * String mappings for integrity_algorithm_t.
 */
mapping_t integrity_algorithm_m[] = {
	{AUTH_UNDEFINED, "UNDEFINED"},
	{AUTH_HMAC_MD5_96, "HMAC_MD5_96"},
	{AUTH_HMAC_SHA1_96, "HMAC_SHA1_96"},
	{AUTH_DES_MAC, "DES_MAC"},
	{AUTH_KPDK_MD5, "KPDK_MD5"},
	{AUTH_AES_XCBC_96, "AES_XCBC_96"},
	{MAPPING_END, NULL}
};


/*
 * Described in header.
 */
signer_t *signer_create(integrity_algorithm_t integrity_algorithm)
{
	switch(integrity_algorithm)
	{
		case AUTH_HMAC_SHA1_96:
		{
			return ((signer_t *) hmac_signer_create(HASH_SHA1));
		}
		case AUTH_HMAC_MD5_96:
		{
			return ((signer_t *) hmac_signer_create(HASH_MD5));
		}
		default:
			return NULL;
	}
}
