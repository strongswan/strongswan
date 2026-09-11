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

/* Multiple blob types and identity types are tried per iteration so the
 * mutator doesn't have to land on the one input shape this fuzzer accepts. */
static builder_part_t blob_types[] = {
	BUILD_BLOB,
	BUILD_BLOB_ASN1_DER,
	BUILD_BLOB_DNSKEY,
	BUILD_BLOB_SSHKEY,
	BUILD_BLOB_PGP,
};

static cred_encoding_type_t cert_encodings[] = {
	CERT_ASN1_DER,
	CERT_PEM,
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

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	dbg_default_set_level(-1);
	library_init(NULL, "fuzz_trusted_pubkey");
	if (!lib->plugins->load(lib->plugins, PLUGINS))
	{
		return 1;
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	certificate_t *cert, *clone;
	public_key_t *key;
	identification_t *subject;
	chunk_t chunk, enc, fp;
	time_t notBefore, notAfter;
	int i, j;

	chunk = chunk_create((u_char*)buf, len);

	for (i = 0; i < countof(blob_types); i++)
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE,
								   CERT_TRUSTED_PUBKEY,
								   blob_types[i], chunk, BUILD_END);
		if (!cert)
		{
			continue;
		}

		/* Basic accessors */
		cert->get_type(cert);
		cert->get_validity(cert, NULL, &notBefore, &notAfter);
		subject = cert->get_subject(cert);
		if (subject)
		{
			cert->has_subject(cert, subject);
		}
		cert->equals(cert, cert);
		cert->issued_by(cert, cert, NULL);

		/* Try every cert encoding */
		for (j = 0; j < countof(cert_encodings); j++)
		{
			if (cert->get_encoding(cert, cert_encodings[j], &enc))
			{
				chunk_free(&enc);
			}
		}

		/* Clone exercises ref/copy semantics */
		clone = cert->get_ref(cert);
		if (clone)
		{
			clone->destroy(clone);
		}

		/* Extract the underlying public key and exercise it */
		key = cert->get_public_key(cert);
		if (key)
		{
			key->get_type(key);
			key->get_keysize(key);
			for (j = 0; j < countof(keyid_types); j++)
			{
				if (key->get_fingerprint(key, keyid_types[j], &fp))
				{
					/* fingerprint is owned by the key, do not free */
				}
			}
			for (j = 0; j < countof(pubkey_encodings); j++)
			{
				if (key->get_encoding(key, pubkey_encodings[j], &enc))
				{
					chunk_free(&enc);
				}
			}
			key->destroy(key);
		}

		cert->destroy(cert);
	}
	return 0;
}
