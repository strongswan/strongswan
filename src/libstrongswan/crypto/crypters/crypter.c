/**
 * @file crypter.c
 * 
 * @brief Generic constructor for crypter_t.
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


#include "crypter.h"

#include <crypto/crypters/aes_cbc_crypter.h>
#include <crypto/crypters/des_crypter.h>


/** 
 * String mappings for encryption_algorithm_t.
 */
mapping_t encryption_algorithm_m[] = {
	{ENCR_UNDEFINED, "UNDEFINED"},
	{ENCR_DES_IV64, "DES_IV64"},
	{ENCR_DES, "DES"},
	{ENCR_3DES, "3DES"},
	{ENCR_RC5, "RC5"},
	{ENCR_IDEA, "IDEA"},
	{ENCR_CAST, "CAST"},
	{ENCR_BLOWFISH, "BLOWFISH"},
	{ENCR_3IDEA, "3IDEA"},
	{ENCR_DES_IV32, "DES_IV32"},
	{ENCR_NULL, "NULL"},
	{ENCR_AES_CBC, "AES_CBC"},
	{ENCR_AES_CTR, "AES_CTR"},
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
		case ENCR_DES:
		case ENCR_3DES:
		{
			return (crypter_t*)des_crypter_create(encryption_algorithm);
		}
		default:
			return NULL;
	}
}
