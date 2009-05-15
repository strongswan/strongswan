/* crypto interfaces
 * Copyright (C) 1998-2001  D. Hugh Redelmeier
 * Copyright (C) 2007-2009 Andreas Steffen
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

#include <gmp.h>

#include <freeswan.h>

#include <crypto/crypters/crypter.h>
#include <crypto/hashers/hasher.h>

#include "constants.h"
#include "defs.h"
#include "crypto.h"
#include "ike_alg.h"
#include "log.h"

extern struct encrypt_desc encrypt_desc_3des;
extern struct encrypt_desc encrypt_desc_blowfish;
extern struct encrypt_desc encrypt_desc_aes;
extern struct encrypt_desc encrypt_desc_twofish;
extern struct encrypt_desc encrypt_desc_twofish_ssh;
extern struct encrypt_desc encrypt_desc_serpent;

extern struct hash_desc hash_desc_md5;
extern struct hash_desc hash_desc_sha1;
extern struct hash_desc hash_desc_sha2_256;
extern struct hash_desc hash_desc_sha2_384;
extern struct hash_desc hash_desc_sha2_512;

/* moduli and generator. */

static MP_INT
	modp1024_modulus,
	modp1536_modulus,
	modp2048_modulus,
	modp3072_modulus,
	modp4096_modulus,
	modp6144_modulus,
	modp8192_modulus;

MP_INT groupgenerator;  /* MODP group generator (2) */



void init_crypto(void)
{
	enumerator_t *enumerator;
	encryption_algorithm_t encryption_alg;
	hash_algorithm_t hash_alg;
	bool no_md5  = TRUE;
	bool no_sha1 = TRUE;

	enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &hash_alg))
	{
		const struct hash_desc *desc;

		switch (hash_alg)
		{
			case HASH_SHA1:
				desc = &hash_desc_sha1;
				no_sha1 = FALSE;
				break;
			case HASH_SHA256:
				desc = &hash_desc_sha2_256;
				break;
			case HASH_SHA384:
				desc = &hash_desc_sha2_384;
				break;
			case HASH_SHA512:
				desc = &hash_desc_sha2_512;
				break;
			case HASH_MD5:
				desc = &hash_desc_md5;
				no_md5 = FALSE;
				break;
			default:
				continue;
		}
		ike_alg_add((struct ike_alg *)desc);
	}
	enumerator->destroy(enumerator);

	if (no_sha1)
	{
		exit_log("pluto cannot run without a SHA-1 hasher");
	}
	if (no_md5)
	{
		exit_log("pluto cannot run without an MD5 hasher");
	}
		
	enumerator = lib->crypto->create_crypter_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &encryption_alg))
	{
		const struct encrypt_desc *desc;
 
		switch (encryption_alg)
		{
			case ENCR_3DES:
				desc = &encrypt_desc_3des;
				break;
			case ENCR_BLOWFISH:
				desc = &encrypt_desc_blowfish;
				break;
			case ENCR_AES_CBC:
				desc = &encrypt_desc_aes;
				break;
			case ENCR_TWOFISH_CBC:
				desc = &encrypt_desc_twofish;
				ike_alg_add((struct ike_alg *)&encrypt_desc_twofish_ssh);
				break;
			case ENCR_SERPENT_CBC:
				desc = &encrypt_desc_serpent;
				break;
			default:
				continue;			
		}
		ike_alg_add((struct ike_alg *)desc);
	}
	enumerator->destroy(enumerator);

	if (mpz_init_set_str(&groupgenerator, MODP_GENERATOR, 10) != 0
	 || mpz_init_set_str(&modp1024_modulus, MODP1024_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp1536_modulus, MODP1536_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp2048_modulus, MODP2048_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp3072_modulus, MODP3072_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp4096_modulus, MODP4096_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp6144_modulus, MODP6144_MODULUS, 16) != 0
	 || mpz_init_set_str(&modp8192_modulus, MODP8192_MODULUS, 16) != 0)
	{
		exit_log("mpz_init_set_str() failed in init_crypto()");
	}
#ifdef SELF_TEST
	if (!ike_alg_test())
	{
		exit_log("pluto cannot run due to failed crypto self-test");
	}
#endif
}

void free_crypto(void)
{
	mpz_clear(&groupgenerator);
	mpz_clear(&modp1024_modulus);
	mpz_clear(&modp1536_modulus);
	mpz_clear(&modp2048_modulus);
	mpz_clear(&modp3072_modulus);
	mpz_clear(&modp4096_modulus);
	mpz_clear(&modp6144_modulus);
	mpz_clear(&modp8192_modulus);
}

/* Oakley group description
 *
 * See RFC2409 "The Internet key exchange (IKE)" 6.
 */

const struct oakley_group_desc unset_group = {0, NULL, 0};      /* magic signifier */

const struct oakley_group_desc oakley_group[OAKLEY_GROUP_SIZE] = {
#   define BYTES(bits) (((bits) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)
	{ OAKLEY_GROUP_MODP1024, &modp1024_modulus, BYTES(1024) },
	{ OAKLEY_GROUP_MODP1536, &modp1536_modulus, BYTES(1536) },
	{ OAKLEY_GROUP_MODP2048, &modp2048_modulus, BYTES(2048) },
	{ OAKLEY_GROUP_MODP3072, &modp3072_modulus, BYTES(3072) },
	{ OAKLEY_GROUP_MODP4096, &modp4096_modulus, BYTES(4096) },
	{ OAKLEY_GROUP_MODP6144, &modp6144_modulus, BYTES(6144) },
	{ OAKLEY_GROUP_MODP8192, &modp8192_modulus, BYTES(8192) },
#   undef BYTES
};

const struct oakley_group_desc *lookup_group(u_int16_t group)
{
	int i;

	for (i = 0; i != countof(oakley_group); i++)
		if (group == oakley_group[i].group)
			return &oakley_group[i];
	return NULL;
}

/**
 * Converts IKEv1 encryption algorithm name to crypter name
 */
encryption_algorithm_t oakley_to_encryption_algorithm(int alg)
{
	switch (alg)
	{
		case OAKLEY_DES_CBC:
			return ENCR_DES;
		case OAKLEY_IDEA_CBC:
			return ENCR_IDEA; 
		case OAKLEY_BLOWFISH_CBC:
			return ENCR_BLOWFISH;
		case OAKLEY_RC5_R16_B64_CBC:
			return ENCR_RC5;
		case OAKLEY_3DES_CBC:
			return ENCR_3DES;
		case OAKLEY_CAST_CBC:
			return ENCR_CAST;
		case OAKLEY_AES_CBC:
			return ENCR_AES_CBC;
		case OAKLEY_SERPENT_CBC:
			return ENCR_SERPENT_CBC;
		case OAKLEY_TWOFISH_CBC:
		case OAKLEY_TWOFISH_CBC_SSH:
			return ENCR_TWOFISH_CBC;
		default:
			return ENCR_UNDEFINED;
	}
}

/**
 * Converts IKEv1 hash algorithm name to hasher name
 */
hash_algorithm_t oakley_to_hash_algorithm(int alg)
{
	switch (alg)
	{
		case OAKLEY_MD5:
			return HASH_MD5;
		case OAKLEY_SHA:
			return HASH_SHA1;
		case OAKLEY_SHA2_256:
			return HASH_SHA256;
		case OAKLEY_SHA2_384:
			return HASH_SHA384;
		case OAKLEY_SHA2_512:
			return HASH_SHA512;
		default:
			return HASH_UNKNOWN;
	}
}

/**
 * Converts IKEv1 hash algorithm name to IKEv2 prf name
 */
pseudo_random_function_t oakley_to_prf(int alg)
{
	switch (alg)
	{
		case OAKLEY_MD5:
			return PRF_HMAC_MD5;
		case OAKLEY_SHA:
			return PRF_HMAC_SHA1;
		case OAKLEY_SHA2_256:
			return PRF_HMAC_SHA2_256;
		case OAKLEY_SHA2_384:
			return PRF_HMAC_SHA2_384;
		case OAKLEY_SHA2_512:
			return PRF_HMAC_SHA2_512;
		default:
			return PRF_UNDEFINED;
	}
}
