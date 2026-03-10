/*
 * Copyright (C) 2026 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2014-2016 Andreas Steffen
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

#include "pki.h"

#include <asn1/asn1.h>
#include <asn1/oid.h>

/**
 * Known key types
 */
static struct {
	char *name;
	key_type_t type;
} key_types[] = {
	{ "rsa", KEY_RSA, },
	{ "ecdsa", KEY_ECDSA, },
	{ "ed25519", KEY_ED25519, },
	{ "ed448", KEY_ED448, },
	{ "mldsa44", KEY_ML_DSA_44, },
	{ "mldsa65", KEY_ML_DSA_65, },
	{ "mldsa87", KEY_ML_DSA_87, },
	{ "mldsa44-rsa2048pss", KEY_MLDSA44_RSA2048_PSS, },
	{ "mldsa44-rsa2048pkcs15", KEY_MLDSA44_RSA2048_PKCS15, },
	{ "mldsa44-ed25519", KEY_MLDSA44_ED25519, },
	{ "mldsa44-ecdsa256", KEY_MLDSA44_ECDSA_P256, },
	{ "mldsa65-rsa3072pss", KEY_MLDSA65_RSA3072_PSS, },
	{ "mldsa65-rsa3072pkcs15", KEY_MLDSA65_RSA3072_PKCS15, },
	{ "mldsa65-rsa4096pss", KEY_MLDSA65_RSA4096_PSS, },
	{ "mldsa65-rsa4096pkcs15", KEY_MLDSA65_RSA4096_PKCS15, },
	{ "mldsa65-ecdsa256", KEY_MLDSA65_ECDSA_P256, },
	{ "mldsa65-ecdsa384", KEY_MLDSA65_ECDSA_P384, },
	{ "mldsa65-ecdsa256-bp", KEY_MLDSA65_ECDSA_BPP256R1, },
	{ "mldsa65-ed25519", KEY_MLDSA65_ED25519, },
	{ "mldsa87-ecdsa384", KEY_MLDSA87_ECDSA_P384, },
	{ "mldsa87-ecdsa384-bp", KEY_MLDSA87_ECDSA_BPP384R1, },
	{ "mldsa87-ed448", KEY_MLDSA87_ED448, },
	{ "mldsa87-rsa3072pss", KEY_MLDSA87_RSA3072_PSS, },
	{ "mldsa87-rsa4096pss", KEY_MLDSA87_RSA4096_PSS, },
	{ "mldsa87-ecdsa521", KEY_MLDSA87_ECDSA_P521, },
};

/**
 * Try to match the given key type name.
 */
static key_type_t get_key_type(char *name)
{
	int i;

	for (i = 0; i < countof(key_types); i++)
	{
		if (streq(name, key_types[i].name))
		{
			return key_types[i].type;
		}
	}
	return KEY_ANY;
}

/**
 * Known elliptic curves.
 */
static const struct {
	char *name;
	int oid;
} known_curves[] = {
	{ "p256", OID_PRIME256V1, },
	{ "p384", OID_SECT384R1, },
	{ "p521", OID_SECT521R1, },
	{ "p-256", OID_PRIME256V1, },
	{ "p-384", OID_SECT384R1, },
	{ "p-521", OID_SECT521R1, },
	{ "secp256r1", OID_PRIME256V1, },
	{ "secp384r1", OID_SECT384R1, },
	{ "secp521r1", OID_SECT521R1, },
	{ "bp256", OID_BRAINPOOLP256R1, },
	{ "bp384", OID_BRAINPOOLP384R1, },
	{ "bp512", OID_BRAINPOOLP512R1, },
	{ "brainpoolP256r1", OID_BRAINPOOLP256R1, },
	{ "brainpoolP384r1", OID_BRAINPOOLP384R1, },
	{ "brainpoolP512r1", OID_BRAINPOOLP512R1, },
};

/**
 * Try to find an elliptic curve with the given name or parse it as an OID.
 */
static bool get_curve(char *name, chunk_t *curve)
{
	int i;

	if (strchr(name, '.'))
	{
		*curve = asn1_wrap(ASN1_OID, "m", asn1_oid_from_string(name));
		return TRUE;
	}

	for (i = 0; i < countof(known_curves); i++)
	{
		if (strcaseeq(name, known_curves[i].name))
		{
			*curve = asn1_build_known_oid(known_curves[i].oid);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Generate a private key
 */
static int gen()
{
	cred_encoding_type_t form = PRIVKEY_ASN1_DER;
	key_type_t type = KEY_RSA;
	u_int size = 0, shares = 0, threshold = 1;
	private_key_t *key;
	chunk_t encoding, curve = chunk_empty;
	bool safe_primes = FALSE;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 't':
				type = get_key_type(arg);
				if (type == KEY_ANY)
				{
					return command_usage("invalid key type");
				}
				continue;
			case 'c':
				chunk_free(&curve);
				if (!get_curve(arg, &curve))
				{
					return command_usage("invalid elliptic curve");
				}
				continue;
			case 'f':
				if (!get_form(arg, &form, CRED_PRIVATE_KEY))
				{
					return command_usage("invalid key output format");
				}
				continue;
			case 's':
				size = atoi(arg);
				if (!size)
				{
					return command_usage("invalid key size");
				}
				continue;
			case 'p':
				safe_primes = TRUE;
				continue;
			case 'n':
				shares = atoi(arg);
				if (shares < 2)
				{
					return command_usage("invalid number of key shares");
				}
				continue;
			case 'l':
				threshold = atoi(arg);
				if (threshold < 1)
				{
					return command_usage("invalid key share threshold");
				}
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --gen option");
		}
		break;
	}
	/* default values for key types with variable key size */
	if (!size)
	{
		switch (type)
		{
			case KEY_RSA:
				size = 2048;
				break;
			case KEY_ECDSA:
				size = 384;
				break;
			default:
				break;
		}
	}
	if (type == KEY_RSA && shares)
	{
		if (threshold > shares)
		{
			return command_usage("threshold is larger than number of shares");
		}
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_SAFE_PRIMES,
							BUILD_SHARES, shares, BUILD_THRESHOLD, threshold,
							BUILD_END);
	}
	else if (type == KEY_RSA && safe_primes)
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_SAFE_PRIMES, BUILD_END);
	}
	else if (type == KEY_ECDSA && curve.len)
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_ECDSA_CURVE, curve, BUILD_END);
	}
	else
	{
		key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							BUILD_KEY_SIZE, size, BUILD_END);
	}
	chunk_free(&curve);
	if (!key)
	{
		fprintf(stderr, "private key generation failed\n");
		return 1;
	}
	if (!key->get_encoding(key, form, &encoding))
	{
		fprintf(stderr, "private key encoding failed\n");
		key->destroy(key);
		return 1;
	}
	key->destroy(key);
	set_file_mode(stdout, form);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		fprintf(stderr, "writing private key failed\n");
		free(encoding.ptr);
		return 1;
	}
	free(encoding.ptr);
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		gen, 'g', "gen", "generate a new private key",
		{"[--type <key type>] [--size bits] [--curve <name|oid>] [--safe-primes]",
		 "[--shares n] [--threshold l] [--outform der|pem]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"type",		't', 1, "type of key (see man page), default: rsa"},
			{"size",		's', 1, "keylength in bits, default: rsa 2048, ecdsa 384"},
			{"curve",		'c', 1, "curve for ecdsa key (name or oid, --size is ignored)"},
			{"safe-primes", 'p', 0, "generate rsa safe primes"},
			{"shares",		'n', 1, "number of private rsa key shares"},
			{"threshold",	'l', 1, "minimum number of participating rsa key shares"},
			{"outform",		'f', 1, "encoding of generated private key, default: der"},
		}
	});
}
