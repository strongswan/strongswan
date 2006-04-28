/**
 * @file crypter.c
 * 
 * @brief Generic constructor for crypter_t.
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


#include "crypter.h"

#include <crypto/crypters/aes_cbc_crypter.h>


/** 
 * String mappings for encryption_algorithm_t.
 */
mapping_t encryption_algorithm_m[] = {
{ENCR_UNDEFINED, "ENCR_UNDEFINED"},
{ENCR_DES_IV64, "ENCR_DES_IV64"},
{ENCR_DES, "ENCR_DES"},
{ENCR_3DES, "ENCR_3DES"},
{ENCR_RC5, "ENCR_RC5"},
{ENCR_IDEA, "ENCR_IDEA"},
{ENCR_CAST, "ENCR_CAST"},
{ENCR_BLOWFISH, "ENCR_BLOWFISH"},
{ENCR_3IDEA, "ENCR_3IDEA"},
{ENCR_DES_IV32, "ENCR_DES_IV32"},
{ENCR_NULL, "ENCR_NULL"},
{ENCR_AES_CBC, "ENCR_AES_CBC"},
{ENCR_AES_CTR, "ENCR_AES_CTR"},
{MAPPING_END, NULL}
};

/* 
 * Described in header.
 */
crypter_t *crypter_create(encryption_algorithm_t encryption_algorithm, size_t key_size)
{
	switch (encryption_algorithm)
	{
		case ENCR_AES_CBC:
		{
			return (crypter_t*)aes_cbc_crypter_create(key_size);
		}
		default:
			return NULL;
	}
}
