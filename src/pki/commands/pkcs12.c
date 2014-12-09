/*
 * Copyright (C) 2014 Tobias Brunner
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

#include <errno.h>

#include "pki.h"

#include <credentials/certificates/x509.h>
#include <credentials/containers/pkcs12.h>

/**
 * Show info about PKCS#12 container
 */
static int show(pkcs12_t *pkcs12)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	private_key_t *key;
	int index = 1;

	printf("Certificates:\n");
	enumerator = pkcs12->create_cert_enumerator(pkcs12);
	while (enumerator->enumerate(enumerator, &cert))
	{
		x509_t *x509 = (x509_t*)cert;

		if (x509->get_flags(x509) & X509_CA)
		{
			printf("[%2d] \"%Y\" (CA)\n", index++, cert->get_subject(cert));
		}
		else
		{
			printf("[%2d] \"%Y\"\n", index++, cert->get_subject(cert));
		}
	}
	enumerator->destroy(enumerator);

	printf("Private keys:\n");
	enumerator = pkcs12->create_key_enumerator(pkcs12);
	while (enumerator->enumerate(enumerator, &key))
	{
		printf("[%2d] %N %d bits\n", index++, key_type_names,
			   key->get_type(key), key->get_keysize(key));
	}
	enumerator->destroy(enumerator);
	return 0;
}

/**
 * Handle PKCs#12 containers
 */
static int pkcs12()
{
	char *arg, *file = NULL;
	pkcs12_t *p12 = NULL;
	int res = 1;
	enum {
		OP_NONE,
		OP_LIST,
	} op = OP_NONE;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'i':
				file = arg;
				continue;
			case 'l':
				if (op != OP_NONE)
				{
					goto invalid;
				}
				op = OP_LIST;
				continue;
			case EOF:
				break;
			default:
			invalid:
				return command_usage("invalid --pkcs12 option");
		}
		break;
	}

	if (op != OP_LIST)
	{
		return command_usage(NULL);
	}

	if (file)
	{
		p12 = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS12,
								  BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		chunk_t chunk;

		set_file_mode(stdin, CERT_ASN1_DER);
		if (!chunk_from_fd(0, &chunk))
		{
			fprintf(stderr, "reading input failed: %s\n", strerror(errno));
			return 1;
		}
		p12 = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS12,
								  BUILD_BLOB, chunk, BUILD_END);
		free(chunk.ptr);
	}

	if (!p12)
	{
		fprintf(stderr, "reading input failed!\n");
		goto end;
	}

	res = show(p12);
end:
	if (p12)
	{
		p12->container.destroy(&p12->container);
	}
	return res;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		pkcs12, 'u', "pkcs12", "PKCS#12 functions",
		{"--list [--in file]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"list",	'l', 0, "list certificates and keys"},
		}
	});
}
