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

#include <errno.h>

#include "pki.h"

#include <credentials/certificates/x509.h>
#include <credentials/containers/pem.h>

/**
 * Show info about PEM certificate bundle
 */
static int show(pem_t *bundle)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	int index = 1;

	enumerator = bundle->create_cert_enumerator(bundle);
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
	return 0;
}

/**
 * Export a certificate from a PEM certificate bundle
 */
static int export(pem_t *bundle, int index, char *outform)
{
	cred_encoding_type_t form = CERT_ASN1_DER;
	enumerator_t *enumerator;
	certificate_t *cert;
	chunk_t encoding;
	int i = 1;

	if (outform && !get_form(outform, &form, CRED_CERTIFICATE))
	{
		return command_usage("invalid output format");
	}

	enumerator = bundle->create_cert_enumerator(bundle);
	while (enumerator->enumerate(enumerator, &cert))
	{
		if (i++ == index)
		{
			if (cert->get_encoding(cert, form, &encoding))
			{
				set_file_mode(stdout, form);
				if (fwrite(encoding.ptr, encoding.len, 1, stdout) == 1)
				{
					free(encoding.ptr);
					enumerator->destroy(enumerator);
					return 0;
				}
				free(encoding.ptr);
			}
			fprintf(stderr, "certificate export failed\n");
			enumerator->destroy(enumerator);
			return 1;
		}
	}
	enumerator->destroy(enumerator);

	fprintf(stderr, "invalid index %d\n", index);
	return 1;
}

/**
 * Handle PEM certificate bundles
 */
static int bundle()
{
	char *arg, *file = NULL, *outform = NULL;
	pem_t *pem = NULL;
	int res = 1, index = 0;
	enum {
		OP_NONE,
		OP_LIST,
		OP_EXPORT,
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
			case 'e':
				if (op != OP_NONE)
				{
					goto invalid;
				}
				op = OP_EXPORT;
				index = atoi(arg);
				continue;
			case 'f':
				outform = arg;
				continue;
			case EOF:
				break;
			default:
			invalid:
				return command_usage("invalid --bundle option");
		}
		break;
	}

	if (file)
	{
		pem = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PEM,
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
		pem = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PEM,
								 BUILD_BLOB, chunk, BUILD_END);
		free(chunk.ptr);
	}

	if (!pem)
	{
		fprintf(stderr, "reading input failed!\n");
		goto end;
	}

	switch (op)
	{
		case OP_LIST:
			res = show(pem);
			break;
		case OP_EXPORT:
			res = export(pem, index, outform);
			break;
		default:
			pem->container.destroy(&pem->container);
			return command_usage(NULL);
	}

end:
	if (pem)
	{
		pem->container.destroy(&pem->container);
	}
	return res;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		bundle, 'b', "bundle", "PEM certificate bundle functions",
		{"--export index|--list [--in file]",
		 "[--outform der|pem]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"list",	'l', 0, "list certificates"},
			{"export",	'e', 1, "export the certificate with the given index"},
			{"outform",	'f', 1, "encoding of exported certificate, default: der"},
		}
	});
}
