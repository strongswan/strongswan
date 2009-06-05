/*
 * Copyright (C) 2002-2009 Andreas Steffen
 *
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
 
#include "pgp.h"

ENUM_BEGIN(pgp_packet_tag_names, PGP_PKT_RESERVED, PGP_PKT_PUBLIC_SUBKEY,
	"Reserved",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret Key Packet",
	"Public Key Packet",
	"Secret Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public Subkey Packet"
);
ENUM_NEXT(pgp_packet_tag_names, PGP_PKT_USER_ATTRIBUTE, PGP_PKT_MOD_DETECT_CODE, PGP_PKT_PUBLIC_SUBKEY,
	"User Attribute Packet",
	"Sym. Encrypted and Integrity Protected Data Packet",
	"Modification Detection Code Packet"
);
ENUM_END(pgp_packet_tag_names, PGP_PKT_MOD_DETECT_CODE);


ENUM_BEGIN(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_RSA, PGP_PUBKEY_ALG_RSA_SIGN_ONLY,
	"RSA",
	"RSA_ENC_ONLY",
	"RSA_SIGN_ONLY"
);
ENUM_NEXT(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_ELGAMAL_ENC_ONLY, PGP_PUBKEY_ALG_DIFFIE_HELLMAN, PGP_PUBKEY_ALG_RSA_SIGN_ONLY,
	"ELGAMAL_ENC_ONLY",
	"DSA",
	"ECC",
	"ECDSA",
	"ELGAMAL",
	"DIFFIE_HELLMAN"
);
ENUM_END(pgp_pubkey_alg_names, PGP_PUBKEY_ALG_DIFFIE_HELLMAN);


ENUM(pgp_sym_alg_names, PGP_SYM_ALG_PLAIN, PGP_SYM_ALG_TWOFISH,
	"PLAINTEXT",
	"IDEA",
	"3DES",
	"CAST5",
	"BLOWFISH",
	"SAFER",
	"DES",
	"AES_128",
	"AES_192",
	"AES_256",
	"TWOFISH"
);

/*
 * Defined in header.
 */
size_t pgp_length(chunk_t *blob, size_t len)
{
	size_t size = 0;

	if (len > blob->len)
	{
		return PGP_INVALID_LENGTH;
	}
	blob->len -= len;

	while (len-- > 0)
	{
		size = 256*size + *blob->ptr++;
	}
	return size;
}

