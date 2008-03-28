/*
 * Copyright (C) 2007 Bruno Krieg, Daniel Wydler
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
 *
 * $Id$
 */

#include <stdio.h>

#include <debug.h>
#include <crypto/signers/signer.h>
#include "fips.h"

extern const u_char FIPS_rodata_start[];
extern const u_char FIPS_rodata_end[];
extern const void *FIPS_text_start();
extern const void *FIPS_text_end();

/**
 * Described in header
 */
bool fips_compute_hmac_signature(const char *key, char *signature)
{
	u_char *text_start = (u_char *)FIPS_text_start();
	u_char *text_end   = (u_char *)FIPS_text_end();
	size_t text_len, rodata_len;
	signer_t *signer;

	if (text_start > text_end)
	{
		DBG1("  TEXT start (%p) > TEXT end (%p",
				text_start, text_end);
		return FALSE;
	}
	text_len = text_end - text_start;
    DBG1("  TEXT:   %p + %6d = %p",
			text_start, (int)text_len, text_end);

	if (FIPS_rodata_start > FIPS_rodata_end)
	{
		DBG1("  RODATA start (%p) > RODATA end (%p",
				FIPS_rodata_start, FIPS_rodata_end);
		return FALSE;
	}
	rodata_len = FIPS_rodata_end - FIPS_rodata_start;
    DBG1("  RODATA: %p + %6d = %p",
			FIPS_rodata_start, (int)rodata_len, FIPS_rodata_end);

    signer = lib->crypto->create_signer(lib->crypto, AUTH_HMAC_SHA1_128);
	if (signer == NULL)
	{
	    DBG1("  SHA-1 HMAC signer could not be created");
		return FALSE;
	}
	else
	{
		chunk_t hmac_key = { (u_char *)key, strlen(key) };
		chunk_t text_chunk = { text_start, text_len };
		chunk_t rodata_chunk = { (u_char *)FIPS_rodata_start, rodata_len };
		chunk_t signature_chunk = chunk_empty;

		signer->set_key(signer, hmac_key);
		signer->allocate_signature(signer, text_chunk, NULL);
		signer->allocate_signature(signer, rodata_chunk, &signature_chunk);
		signer->destroy(signer);

		sprintf(signature, "%#B", &signature_chunk);
		DBG1("  SHA-1 HMAC key: %s", key);
		DBG1("  SHA-1 HMAC sig: %s", signature);
		free(signature_chunk.ptr);
		return TRUE;
	}
}

/**
 * Described in header
 */
bool fips_verify_hmac_signature(const char *key,
								const char *signature)
{
	char current_signature[BUF_LEN];

	if (!fips_compute_hmac_signature(key, current_signature))
	{
		return FALSE;
	}
	return streq(signature, current_signature);
}
