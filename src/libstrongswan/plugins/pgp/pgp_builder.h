/*
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2002-2009 Andreas Steffen
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

/**
 * @defgroup pgp_public_key pgp_public_key
 * @{ @ingroup pgp_p
 */

#ifndef PGP_BUILDER_H_
#define PGP_BUILDER_H_

#include <enum.h>
#include <credentials/keys/public_key.h>

typedef enum pgp_packet_tag_t pgp_packet_tag_t;
typedef enum pgp_pubkey_alg_t pgp_pubkey_alg_t;
typedef enum pgp_sym_alg_t pgp_sym_alg_t;

/**
 * OpenPGP packet tags as defined in section 4.3 of RFC 4880
 */
enum pgp_packet_tag_t {
	PGP_PKT_RESERVED               =  0,
	PGP_PKT_PUBKEY_ENC_SESSION_KEY =  1,
	PGP_PKT_SIGNATURE              =  2,
	PGP_PKT_SYMKEY_ENC_SESSION_KEY =  3,
	PGP_PKT_ONE_PASS_SIGNATURE_PKT =  4,
	PGP_PKT_SECRET_KEY             =  5,
	PGP_PKT_PUBLIC_KEY             =  6,
	PGP_PKT_SECRET_SUBKEY          =  7,
	PGP_PKT_COMPRESSED_DATA        =  8,
	PGP_PKT_SYMKEY_ENC_DATA        =  9,
	PGP_PKT_MARKER                 = 10,
	PGP_PKT_LITERAL_DATA           = 11,
	PGP_PKT_TRUST                  = 12,
	PGP_PKT_USER_ID                = 13,
	PGP_PKT_PUBLIC_SUBKEY          = 14,
	PGP_PKT_USER_ATTRIBUTE         = 17,
	PGP_PKT_SYM_ENC_INT_PROT_DATA  = 18,
	PGP_PKT_MOD_DETECT_CODE        = 19
};

/**
 * Enum names for pgp_packet_tag_t
 */
extern enum_name_t *pgp_packet_tag_names;

/**
 * OpenPGP public key algorithms as defined in section 9.1 of RFC 4880
 */
enum pgp_pubkey_alg_t {
	PGP_PUBKEY_ALG_RSA              =  1,
	PGP_PUBKEY_ALG_RSA_ENC_ONLY     =  2,
	PGP_PUBKEY_ALG_RSA_SIGN_ONLY    =  3,
	PGP_PUBKEY_ALG_ELGAMAL_ENC_ONLY = 16,
	PGP_PUBKEY_ALG_DSA              = 17,
	PGP_PUBKEY_ALG_ECC              = 18,
	PGP_PUBKEY_ALG_ECDSA            = 19,
	PGP_PUBKEY_ALG_ELGAMAL          = 20,
	PGP_PUBKEY_ALG_DIFFIE_HELLMAN   = 21,
};

/**
 * Enum names for pgp_pubkey_alg_t
 */
extern enum_name_t *pgp_pubkey_alg_names;

/**
 * OpenPGP symmetric key algorithms as defined in section 9.2 of RFC 4880
 */
enum pgp_sym_alg_t {
	PGP_SYM_ALG_PLAIN    =  0,
	PGP_SYM_ALG_IDEA     =  1,
	PGP_SYM_ALG_3DES     =  2,
	PGP_SYM_ALG_CAST5    =  3,
	PGP_SYM_ALG_BLOWFISH =  4,
	PGP_SYM_ALG_SAFER    =  5,
	PGP_SYM_ALG_DES      =  6,
	PGP_SYM_ALG_AES_128  =  7,
	PGP_SYM_ALG_AES_192  =  8,
	PGP_SYM_ALG_AES_256  =  9,
	PGP_SYM_ALG_TWOFISH  = 10
};

/**
 * Enum names for pgp_sym_alg_t
 */
extern enum_name_t *pgp_sym_alg_names;

/**
 * Create the builder for a generic or an RSA public key.
 *
 * @param type		type of the key, either KEY_ANY or KEY_RSA
 * @return 			builder instance
 */
builder_t *pgp_public_key_builder(key_type_t type);

/**
 * Create the builder for a RSA private key.
 *
 * @param type		type of the key, KEY_RSA
 * @return 			builder instance
 */
builder_t *pgp_private_key_builder(key_type_t type);

#endif /** PGP_BUILDER_H_ @}*/
