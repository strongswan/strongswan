/*
 * Copyright (C) 2009 Martin Willi
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

#include "pki.h"

/**
 * Generate a private key
 */
static int gen()
{
	key_encoding_type_t form = KEY_PRIV_ASN1_DER;
	key_type_t type = KEY_RSA;
	u_int size = 0;
	private_key_t *key;
	chunk_t encoding;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 't':
				if (streq(arg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(arg, "ecdsa"))
				{
					type = KEY_ECDSA;
				}
				else
				{
					return command_usage("invalid key type");
				}
				continue;
			case 'o':
				if (!get_form(arg, &form, FALSE))
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
			case EOF:
				break;
			default:
				return command_usage("invalid --gen option");
		}
		break;
	}
	/* default key sizes */
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
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							 BUILD_KEY_SIZE, size, BUILD_END);
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
		{"[--type rsa|ecdsa] [--size bits] [--outform der|pem|pgp]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"type",	't', 1, "type of key, default: rsa"},
			{"size",	's', 1, "keylength in bits, default: rsa 2048, ecdsa 384"},
			{"outform",	'f', 1, "encoding of generated private key"},
		}
	});
}

