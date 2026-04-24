/*
 * Copyright (C) 2026 Tobias Brunner
 *
 * Copyright (C) secunet Security Networks AG
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

#include "compsigs_params.h"

#include <asn1/oid.h>

/**
 * Parameters for RSA/PSS signature schemes
 */
#define PSS_PARAMS(bits) static rsa_pss_params_t pss_params_sha##bits = { \
	.hash = HASH_SHA##bits, \
	.mgf1_hash = HASH_SHA##bits, \
	.salt_len = HASH_SIZE_SHA##bits, \
}

PSS_PARAMS(256);
PSS_PARAMS(384);

/**
 * Parameters for composite key types.
 */
static const compsigs_params_t compsigs_params[] = {
	{
		.type = KEY_MLDSA44_RSA2048_PSS,
		.ml_dsa = KEY_ML_DSA_44,
		.ml_dsa_sig = SIGN_ML_DSA_44,
		.ml_dsa_sig_len = 2420,
		.trad = KEY_RSA,
		.trad_key_size = 2048,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PSS, .params = &pss_params_sha256, },
		.prehash = HASH_SHA256,
		.label = "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
	},
	{
		.type = KEY_MLDSA44_RSA2048_PKCS15,
		.ml_dsa = KEY_ML_DSA_44,
		.ml_dsa_sig = SIGN_ML_DSA_44,
		.ml_dsa_sig_len = 2420,
		.trad = KEY_RSA,
		.trad_key_size = 2048,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PKCS1_SHA2_256, },
		.prehash = HASH_SHA256,
		.label = "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
	},
	{
		.type = KEY_MLDSA44_ED25519,
		.ml_dsa = KEY_ML_DSA_44,
		.ml_dsa_sig = SIGN_ML_DSA_44,
		.ml_dsa_sig_len = 2420,
		.trad = KEY_ED25519,
		.trad_key_size = 256,
		.trad_sig = {.scheme = SIGN_ED25519, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA44-Ed25519-SHA512",
	},
	{
		.type = KEY_MLDSA44_ECDSA_P256,
		.ml_dsa = KEY_ML_DSA_44,
		.ml_dsa_sig = SIGN_ML_DSA_44,
		.ml_dsa_sig_len = 2420,
		.trad = KEY_ECDSA,
		.trad_key_size = 256,
		.trad_ecc_curve = OID_PRIME256V1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA256_DER, },
		.prehash = HASH_SHA256,
		.label = "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
	},
	{
		.type = KEY_MLDSA65_RSA3072_PSS,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_RSA,
		.trad_key_size = 3072,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PSS, .params = &pss_params_sha256, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
	},
	{
		.type = KEY_MLDSA65_RSA3072_PKCS15,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_RSA,
		.trad_key_size = 3072,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PKCS1_SHA2_256, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
	},
	{
		.type = KEY_MLDSA65_RSA4096_PSS,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_RSA,
		.trad_key_size = 4096,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PSS, .params = &pss_params_sha384, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
	},
	{
		.type = KEY_MLDSA65_RSA4096_PKCS15,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_RSA,
		.trad_key_size = 4096,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PKCS1_SHA2_384, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
	},
	{
		.type = KEY_MLDSA65_ECDSA_P256,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_ECDSA,
		.trad_key_size = 256,
		.trad_ecc_curve = OID_PRIME256V1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA256_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
	},
	{
		.type = KEY_MLDSA65_ECDSA_P384,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_ECDSA,
		.trad_key_size = 384,
		.trad_ecc_curve = OID_SECT384R1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA384_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
	},
	{
		.type = KEY_MLDSA65_ECDSA_BPP256R1,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_ECDSA,
		.trad_key_size = 256,
		.trad_ecc_curve = OID_BRAINPOOLP256R1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA256_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
	},
	{
		.type = KEY_MLDSA65_ED25519,
		.ml_dsa = KEY_ML_DSA_65,
		.ml_dsa_sig = SIGN_ML_DSA_65,
		.ml_dsa_sig_len = 3309,
		.trad = KEY_ED25519,
		.trad_key_size = 256,
		.trad_sig = {.scheme = SIGN_ED25519, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA65-Ed25519-SHA512",
	},
	{
		.type = KEY_MLDSA87_ECDSA_P384,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_ECDSA,
		.trad_key_size = 384,
		.trad_ecc_curve = OID_SECT384R1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA384_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
	},
	{
		.type = KEY_MLDSA87_ECDSA_BPP384R1,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_ECDSA,
		.trad_key_size = 384,
		.trad_ecc_curve = OID_BRAINPOOLP384R1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA384_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
	},
	{
		.type = KEY_MLDSA87_ED448,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_ED448,
		.trad_key_size = 456,
		.trad_sig = {.scheme = SIGN_ED448, },
		.prehash = HASH_UNKNOWN,
		.label = "COMPSIG-MLDSA87-Ed448-SHAKE256",
	},
	{
		.type = KEY_MLDSA87_RSA3072_PSS,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_RSA,
		.trad_key_size = 3072,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PSS, .params = &pss_params_sha256, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
	},
	{
		.type = KEY_MLDSA87_RSA4096_PSS,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_RSA,
		.trad_key_size = 4096,
		.trad_sig = {.scheme = SIGN_RSA_EMSA_PSS, .params = &pss_params_sha384, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
	},
	{
		.type = KEY_MLDSA87_ECDSA_P521,
		.ml_dsa = KEY_ML_DSA_87,
		.ml_dsa_sig = SIGN_ML_DSA_87,
		.ml_dsa_sig_len = 4627,
		.trad = KEY_ECDSA,
		.trad_key_size = 521,
		.trad_ecc_curve = OID_SECT521R1,
		.trad_sig = {.scheme = SIGN_ECDSA_WITH_SHA512_DER, },
		.prehash = HASH_SHA512,
		.label = "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
	},
};

/*
 * Described in header
 */
const compsigs_params_t *compsigs_params_get(key_type_t type)
{
	int i;

	for (i = 0; i < countof(compsigs_params); i++)
	{
		if (compsigs_params[i].type == type)
		{
			return &compsigs_params[i];
		}
	}
	return NULL;
}
