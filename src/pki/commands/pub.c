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

#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

/**
 * Extract a public key from a private key/certificate
 */
static int pub(int argc, char *argv[])
{
	key_encoding_type_t form = KEY_PUB_SPKI_ASN1_DER;
	credential_type_t type = CRED_PRIVATE_KEY;
	int subtype = KEY_RSA;
	certificate_t *cert;
	private_key_t *private;
	public_key_t *public;
	chunk_t encoding;
	char *file = NULL;
	void *cred;

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", command_opts, NULL))
		{
			case 'h':
				return command_usage(NULL);
			case 't':
				if (streq(optarg, "rsa"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_ECDSA;
				}
				else if (streq(optarg, "x509"))
				{
					type = CRED_CERTIFICATE;
					subtype = CERT_X509;
				}
				else
				{
					return command_usage("invalid input type");
				}
				continue;
			case 'f':
				if (!get_form(optarg, &form, TRUE))
				{
					return command_usage("invalid output format");
				}
				continue;
			case 'i':
				file = optarg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --pub option");
		}
		break;
	}
	if (file)
	{
		cred = lib->creds->create(lib->creds, type, subtype,
									 BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		cred = lib->creds->create(lib->creds, type, subtype,
									 BUILD_FROM_FD, 0, BUILD_END);
	}

	if (type == CRED_PRIVATE_KEY)
	{
		private = cred;
		if (!private)
		{
			fprintf(stderr, "parsing private key failed\n");
			return 1;
		}
		public = private->get_public_key(private);
		private->destroy(private);
	}
	else
	{
		cert = cred;
		if (!cert)
		{
			fprintf(stderr, "parsing certificate failed\n");
			return 1;
		}
		public = cert->get_public_key(cert);
		cert->destroy(cert);
	}
	if (!public)
	{
		fprintf(stderr, "extracting public key failed\n");
		return 1;
	}
	if (!public->get_encoding(public, form, &encoding))
	{
		fprintf(stderr, "public key encoding failed\n");
		public->destroy(public);
		return 1;
	}
	public->destroy(public);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		fprintf(stderr, "writing public key failed\n");
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
		pub, 'p', "pub",
		"extract the public key from a private key/certificate",
		{"[--in file] [--type rsa|ecdsa|x509] [--outform der|pem|pgp]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"type",	't', 1, "type of credential, default: rsa"},
			{"outform",	'f', 1, "encoding of extracted public key"},
		}
	});
}

