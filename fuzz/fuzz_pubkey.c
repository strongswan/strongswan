/*
 * Copyright (C) 2026 Arthur SC Chan
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

#include <library.h>
#include <utils/debug.h>

static builder_part_t blob_types[] = {
	BUILD_BLOB,
	BUILD_BLOB_DNSKEY,
	BUILD_BLOB_SSHKEY,
	BUILD_BLOB_PGP,
};

static cred_encoding_type_t pubkey_encodings[] = {
	PUBKEY_ASN1_DER,
	PUBKEY_PEM,
	PUBKEY_SPKI_ASN1_DER,
	PUBKEY_SSHKEY,
	PUBKEY_DNSKEY,
};

static cred_encoding_type_t keyid_types[] = {
	KEYID_PUBKEY_SHA1,
	KEYID_PUBKEY_INFO_SHA1,
};

static signature_scheme_t verify_schemes[] = {
	SIGN_RSA_EMSA_PKCS1_SHA2_256,
	SIGN_ECDSA_256,
	SIGN_ED25519,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_pubkey");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	public_key_t *key;
	chunk_t chunk, fp, enc;
	chunk_t msg = chunk_from_chars('f', 'u', 'z', 'z');
	int i, j;

	chunk = chunk_create((u_char*)buf, len);

	for (i = 0; i < countof(blob_types); i++)
	{
		key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
								 blob_types[i], chunk, BUILD_END);
		if (!key)
		{
			continue;
		}

		key->get_type(key);
		key->get_keysize(key);
		key->equals(key, key);

		/* All keyid types — exercises hash + fingerprint paths */
		for (j = 0; j < countof(keyid_types); j++)
		{
			key->get_fingerprint(key, keyid_types[j], &fp);
		}

		/* Every encoding format — exercises serializers */
		for (j = 0; j < countof(pubkey_encodings); j++)
		{
			if (key->get_encoding(key, pubkey_encodings[j], &enc))
			{
				chunk_free(&enc);
			}
		}

		/* Verify a bogus signature for each scheme — exercises the verifier
		 * dispatch + algorithm-specific verify entry points. The signature
		 * chunk is just the mutator buffer, so verification fails (or hits
		 * an algorithm mismatch); we don't care about the result. */
		for (j = 0; j < countof(verify_schemes); j++)
		{
			key->verify(key, verify_schemes[j], NULL, msg, chunk);
		}

		key->destroy(key);
	}
	return 0;
}
