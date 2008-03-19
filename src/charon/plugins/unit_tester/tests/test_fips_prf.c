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

#include <utils/linked_list.h>
#include <daemon.h>

/*******************************************************************************
 * fips prf known value test
 ******************************************************************************/
bool fips_prf_test()
{
	prf_t *prf;
	u_int8_t key_buf[] = {
		0xbd, 0x02, 0x9b, 0xbe, 0x7f, 0x51, 0x96, 0x0b,
		0xcf, 0x9e, 0xdb, 0x2b, 0x61, 0xf0, 0x6f, 0x0f,
		0xeb, 0x5a, 0x38, 0xb6
	};
	u_int8_t seed_buf[] = {
		0x00	
	};
	u_int8_t result_buf[] = {
		0x20, 0x70, 0xb3, 0x22, 0x3d, 0xba, 0x37, 0x2f,
		0xde, 0x1c, 0x0f, 0xfc, 0x7b, 0x2e, 0x3b, 0x49,
		0x8b, 0x26, 0x06, 0x14, 0x3c, 0x6c, 0x18, 0xba,
		0xcb, 0x0f, 0x6c, 0x55, 0xba, 0xbb, 0x13, 0x78,
		0x8e, 0x20, 0xd7, 0x37, 0xa3, 0x27, 0x51, 0x16
	};
	chunk_t key = chunk_from_buf(key_buf);
	chunk_t seed = chunk_from_buf(seed_buf);
	chunk_t expected = chunk_from_buf(result_buf);
	chunk_t result;
	
	prf = lib->crypto->create_prf(lib->crypto, PRF_FIPS_SHA1_160);
	if (prf == NULL)
	{
		DBG1(DBG_CFG, "FIPS PRF implementation not found");
		return FALSE;
	}
	prf->set_key(prf, key);
	prf->allocate_bytes(prf, seed, &result);
	prf->destroy(prf);
	if (!chunk_equals(result, expected))
	{
		DBG1(DBG_CFG, "FIPS PRF result invalid:\nexpected: %Bresult: %B",
			 &expected, &result);
		chunk_free(&result);
		return FALSE;
	}
	chunk_free(&result);
	return TRUE;
}

