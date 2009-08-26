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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include <library.h>
#include <credentials/keys/private_key.h>

static int usage(char *error)
{
	FILE *out = stdout;
	
	if (error)
	{
		out = stderr;
		fprintf(out, "%s\n\n", error);
	}
	fprintf(out, "strongSwan %s PKI tool\n", VERSION);
	fprintf(out, "usage:\n");
	fprintf(out, "pki --help\n");
	fprintf(out, "    show this usage information\n");
	fprintf(out, "pki --gen [--type rsa|ecdsa] [--size bits] [--form der|pem|pgp\n");
	fprintf(out, "    generate a new private key\n");
	return !!error;
}

/**
 * Generate a private key
 */
static int gen(int argc, char *argv[])
{
	key_encoding_type_t form = KEY_PRIV_ASN1_DER;
	key_type_t type = KEY_RSA;
	u_int size = 0;
	private_key_t *key;
	chunk_t encoding;
	
	struct option long_opts[] = {
		{ "type", required_argument, NULL, 't' },
		{ "size", required_argument, NULL, 's' },
		{ "form", required_argument, NULL, 'f' },
		{ 0,0,0,0 }
	};
	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case 't':
				if (streq(optarg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa"))
				{
					type = KEY_ECDSA;
				}
				else
				{
					return usage("invalid key type");
				}
				continue;
			case 'f':
				if (streq(optarg, "der"))
				{
					form = KEY_PRIV_ASN1_DER;
				}
				else if (streq(optarg, "pem"))
				{
					form = KEY_PRIV_PEM;
				}
				else if (streq(optarg, "pgp"))
				{
					form = KEY_PRIV_PGP;
				}
				else
				{
					return usage("invalid key format");
				}
				continue;
			case 's':
				size = atoi(optarg);
				if (!size)
				{
					return usage("invalid key size");
				}
				continue;
			case EOF:
				break;
			default:
				return usage("invalid --gen option");
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
 * Library initialization and operation parsing
 */
int main(int argc, char *argv[])
{
	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "gen", no_argument, NULL, 'g' },
		{ 0,0,0,0 }
	};
	
	atexit(library_deinit);
	if (!library_init(STRONGSWAN_CONF))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pki", argv[0]))
	{
		fprintf(stderr, "integrity check of pki failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	lib->plugins->load(lib->plugins, PLUGINDIR,
		lib->settings->get_str(lib->settings, "pki.load", PLUGINS));
	
	switch (getopt_long(argc, argv, "", long_opts, NULL))
	{
		case 'h':
			return usage(NULL);
		case 'g':
			return gen(argc, argv);
		default:
			return usage("invalid operation");
	}
}

