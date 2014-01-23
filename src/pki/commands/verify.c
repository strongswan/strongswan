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

#include <errno.h>

#include "pki.h"

#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

/**
 * Verify a certificate signature
 */
static int verify()
{
	certificate_t *cert, *ca;
	char *file = NULL, *cafile = NULL;
	bool good = FALSE;
	char *arg;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'i':
				file = arg;
				continue;
			case 'c':
				cafile = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --verify option");
		}
		break;
	}

	if (file)
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		chunk_t chunk;

		if (!chunk_from_fd(0, &chunk))
		{
			fprintf(stderr, "reading certificate failed: %s\n", strerror(errno));
			return 1;
		}
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB, chunk, BUILD_END);
		free(chunk.ptr);
	}
	if (!cert)
	{
		fprintf(stderr, "parsing certificate failed\n");
		return 1;
	}
	if (cafile)
	{
		ca = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								BUILD_FROM_FILE, cafile, BUILD_END);
		if (!ca)
		{
			fprintf(stderr, "parsing CA certificate failed\n");
			return 1;
		}
	}
	else
	{
		ca = cert;
	}
	if (cert->issued_by(cert, ca, NULL))
	{
		if (cert->get_validity(cert, NULL, NULL, NULL))
		{
			if (cafile)
			{
				if (ca->get_validity(ca, NULL, NULL, NULL))
				{
					printf("signature good, certificates valid\n");
					good = TRUE;
				}
				else
				{
					printf("signature good, CA certificates not valid now\n");
				}
			}
			else
			{
				printf("signature good, certificate valid\n");
				good = TRUE;
			}
		}
		else
		{
			printf("certificate not valid now\n");
		}
	}
	else
	{
		printf("signature invalid\n");
	}
	if (cafile)
	{
		ca->destroy(ca);
	}
	cert->destroy(cert);

	return good ? 0 : 2;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		verify, 'v', "verify",
		"verify a certificate using the CA certificate",
		{"[--in file] [--cacert file]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "X.509 certificate to verify, default: stdin"},
			{"cacert",	'c', 1, "CA certificate, default: verify self signed"},
		}
	});
}
