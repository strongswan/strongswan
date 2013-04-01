/*
 * Copyright (C) 2013 Tobias Brunner
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

#include "sshkey_builder.h"

#include <bio/bio_reader.h>
#include <utils/debug.h>

/**
 * Load a generic public key from an SSH key blob
 */
static sshkey_public_key_t *parse_public_key(chunk_t blob)
{
	bio_reader_t *reader;
	chunk_t format;

	reader = bio_reader_create(blob);
	if (!reader->read_data32(reader, &format))
	{
		DBG1(DBG_LIB, "invalid key format in SSH key");
		reader->destroy(reader);
		return NULL;
	}
	if (chunk_equals(format, chunk_from_str("ssh-rsa")))
	{
		chunk_t n, e;

		if (!reader->read_data32(reader, &e) ||
			!reader->read_data32(reader, &n))
		{
			DBG1(DBG_LIB, "invalid RSA key in SSH key");
			reader->destroy(reader);
			return NULL;
		}
		reader->destroy(reader);
		return lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
						BUILD_RSA_MODULUS, n, BUILD_RSA_PUB_EXP, e, BUILD_END);
	}
	DBG1(DBG_LIB, "unsupported SSH key format %.*s", (int)format.len,
		 format.ptr);
	reader->destroy(reader);
	return NULL;
}

/**
 * See header.
 */
sshkey_public_key_t *sshkey_public_key_load(key_type_t type, va_list args)
{
	chunk_t blob = chunk_empty;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_SSHKEY:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (blob.ptr && type == KEY_ANY)
	{
		return parse_public_key(blob);
	}
	return NULL;
}
