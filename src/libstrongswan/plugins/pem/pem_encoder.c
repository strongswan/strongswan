/*
 * Copyright (C) 2010 Andreas Steffen
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

#include "pem_encoder.h"

#define BYTES_PER_LINE	48

/**
 * See header.
 */
bool pem_encoder_encode(key_encoding_type_t type, chunk_t *encoding,
						va_list args)
{
	chunk_t asn1;
	char *label;
	u_char *pos;
	size_t len, written, pem_chars, pem_lines;
	chunk_t n, e, d, p, q, exp1, exp2, coeff, to_free = chunk_empty;

	switch (type)
	{
		case KEY_PUB_PEM:
			label ="PUBLIC KEY";
			/* direct PKCS#1 PEM encoding */
			if (key_encoding_args(args, KEY_PART_RSA_PUB_ASN1_DER,
									&asn1, KEY_PART_END) ||
				key_encoding_args(args, KEY_PART_ECDSA_PUB_ASN1_DER,
									&asn1, KEY_PART_END))
			{
				break;
			}
			/* indirect PEM encoding from components */
			if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
									KEY_PART_RSA_PUB_EXP, &e, KEY_PART_END))
			{
				if (lib->encoding->encode(lib->encoding, KEY_PUB_SPKI_ASN1_DER,
									NULL, &asn1, KEY_PART_RSA_MODULUS, n,
									KEY_PART_RSA_PUB_EXP, e, KEY_PART_END))
				{
					to_free = asn1;
					break;
				}
			}
			return FALSE;
		case KEY_PRIV_PEM:
			label ="RSA PRIVATE KEY";
			/* direct PKCS#1 PEM encoding */
			if (key_encoding_args(args, KEY_PART_RSA_PRIV_ASN1_DER,
									&asn1, KEY_PART_END))
			{
				break;
			}
			/* indirect PEM encoding from components */
			if (key_encoding_args(args, KEY_PART_RSA_MODULUS, &n,
							KEY_PART_RSA_PUB_EXP, &e, KEY_PART_RSA_PRIV_EXP, &d,
							KEY_PART_RSA_PRIME1, &p, KEY_PART_RSA_PRIME2, &q,
							KEY_PART_RSA_EXP1, &exp1, KEY_PART_RSA_EXP2, &exp2,
							KEY_PART_RSA_COEFF, &coeff, KEY_PART_END))
			{
				if (lib->encoding->encode(lib->encoding, KEY_PRIV_ASN1_DER, NULL,
							&asn1, KEY_PART_RSA_MODULUS, n,
							KEY_PART_RSA_PUB_EXP, e, KEY_PART_RSA_PRIV_EXP, d,
							KEY_PART_RSA_PRIME1, p, KEY_PART_RSA_PRIME2, q,
							KEY_PART_RSA_EXP1, exp1, KEY_PART_RSA_EXP2, exp2,
							KEY_PART_RSA_COEFF, coeff, KEY_PART_END))
				{
					to_free = asn1;
					break;
				}
			}
			if (key_encoding_args(args, KEY_PART_ECDSA_PRIV_ASN1_DER,
								   &asn1, KEY_PART_END))
			{
				label ="EC PRIVATE KEY";
				break;
			}
			return FALSE;
		default:
			return FALSE;
	}

	/* compute and allocate maximum size of PEM object */
	pem_chars = 4*(asn1.len + 2)/3;
	pem_lines = (asn1.len + BYTES_PER_LINE - 1) / BYTES_PER_LINE;
	*encoding = chunk_alloc(5 + 2*(6 + strlen(label) + 6) + 3 + pem_chars + pem_lines);
	pos = encoding->ptr;
	len = encoding->len;

	/* write PEM header */
	written = snprintf(pos, len, "-----BEGIN %s-----\n", label);
	pos += written;
	len -= written;

	/* write PEM body */
	while (pem_lines--)
	{
		chunk_t asn1_line, pem_line;

		asn1_line = chunk_create(asn1.ptr, min(asn1.len, BYTES_PER_LINE));
		asn1.ptr += asn1_line.len;
		asn1.len -= asn1_line.len;
		pem_line =  chunk_to_base64(asn1_line, pos);
		pos += pem_line.len;
		len -= pem_line.len;
		*pos = '\n';
		pos++;
		len--;
	}

	chunk_clear(&to_free);

	/* write PEM trailer */
	written = snprintf(pos, len, "-----END %s-----", label);
	pos += written;
	len -= written;

	/* replace termination null character with newline */
	*pos = '\n';
	pos++;
	len--;

	/* compute effective length of PEM object */
	encoding->len = pos - encoding->ptr;
	return TRUE;
}

