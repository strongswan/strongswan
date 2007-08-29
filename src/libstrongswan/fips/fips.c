/**
 * @file fips.c
 * 
 * @brief Implementation of the libstrongswan integrity test.
 * 
 */

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
 */

#include "fips.h"
#include <debug.h>
#include <crypto/signers/hmac_signer.h>

extern const unsigned char FIPS_rodata_start[];
extern const unsigned char FIPS_rodata_end[];
extern const void *FIPS_text_start();
extern const void *FIPS_text_end();

/**
 * Described in header
 */
char* fips_compute_hmac_signature(const char *key)
{
	chunk_t hmac_key = { key, strlen(key) };

    hmac_signer_t *signer = hmac_signer_create(HASH_SHA1, HASH_SIZE_SHA1);

    DBG1("  TEXT:   %p + %6d = %p",
		 FIPS_text_start(),
		(int)( (size_t)FIPS_text_end() - (size_t)FIPS_text_start() ),
		FIPS_text_end());
    DBG1("  RODATA: %p + %6d = %p",
		FIPS_rodata_start,
        (int)( (size_t)FIPS_rodata_end - (size_t)FIPS_rodata_start ),
        FIPS_rodata_end);

	if (signer == NULL)
	{
	    DBG1("  fips hmac signer could not be created");
		return NULL;
	}
	signer->signer_interface.set_key((signer_t *)signer, hmac_key);
	signer->signer_interface.destroy((signer_t *)signer);
	return strdup("01020304050607080901011121314151617181920");
}

/**
 * Described in header
 */
status_t fips_verify_hmac_signature(const char *signature,
									const char *key)
{
	status_t status;
	char *current_signature = fips_compute_hmac_signature(key);

	if (current_signature == NULL)
	{
		status = FAILED;
	}
	else
	{
		status = streq(signature, current_signature)? SUCCESS:VERIFY_ERROR;
		free(current_signature);
	}
	return status;
}
