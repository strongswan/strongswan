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

#include "sshkey_encoder.h"

#include <bio/bio_writer.h>

/**
 * Encode the public key as Base64 encoded SSH key blob
 */
static bool build_public_key(chunk_t *encoding, va_list args)
{
	bio_writer_t *writer;
	chunk_t n, e;

	if (cred_encoding_args(args, CRED_PART_RSA_MODULUS, &n,
						   CRED_PART_RSA_PUB_EXP, &e, CRED_PART_END))
	{
		writer = bio_writer_create(0);
		writer->write_data32(writer, chunk_from_str("ssh-rsa"));

		writer->write_data32(writer, e);
		writer->write_data32(writer, n);
		*encoding = chunk_to_base64(writer->get_buf(writer), NULL);
		writer->destroy(writer);
		return TRUE;
	}
	return FALSE;
}

bool sshkey_encoder_encode(cred_encoding_type_t type, chunk_t *encoding,
						   va_list args)
{
	switch (type)
	{
		case PUBKEY_SSHKEY:
			return build_public_key(encoding, args);
		default:
			return FALSE;
	}
}
