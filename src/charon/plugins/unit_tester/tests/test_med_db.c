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

#include <library.h>
#include <daemon.h>
#include <utils/enumerator.h>

#include <unistd.h>

/*******************************************************************************
 * fetch public key from mediation database
 ******************************************************************************/

bool test_med_db()
{
	char keyid_buf[] = {
		0xed,0x90,0xe6,0x4f,0xec,0xa2,0x1f,0x4b,
		0x68,0x97,0x99,0x24,0x22,0xe0,0xde,0x21,
		0xb9,0xd6,0x26,0x29
	};
	chunk_t keyid = chunk_from_buf(keyid_buf);
	identification_t *id, *found;
	enumerator_t *enumerator;
	public_key_t *public;
	auth_cfg_t *auth;
	bool good = FALSE;
	
	id = identification_create_from_encoding(ID_KEY_ID, keyid);
	enumerator = charon->credentials->create_public_enumerator(
									charon->credentials, KEY_ANY, id, NULL);
	while (enumerator->enumerate(enumerator, &public, &auth))
	{
		found = public->get_id(public, ID_PUBKEY_SHA1);
		good = chunk_equals(id->get_encoding(id), found->get_encoding(found));
	}
	enumerator->destroy(enumerator);
	id->destroy(id);
	return good;
}

