/*
 * Copyright (C) 2015 Martin Willi
 * Copyright (C) 2015 revosec AG
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

#include <utils/debug.h>
#include <credentials/certificates/certificate.h>

/**
 * Make a 8-byte /64 prefix from a given IPv6 address string
 */
static bool make_prefix(char *str, chunk_t *prefix)
{
	host_t *host;
	chunk_t enc;
	char zero[8] = {};

	host = host_create_from_string(str, 0);
	if (!host)
	{
		return FALSE;
	}
	if (host->get_family(host) != AF_INET6)
	{
		host->destroy(host);
		return FALSE;
	}
	enc = host->get_address(host);
	if (enc.len != 16 || !memeq(enc.ptr + 8, zero, 8))
	{
		host->destroy(host);
		return FALSE;
	}
	*prefix = chunk_clone(chunk_create(enc.ptr, 8));
	host->destroy(host);
	return TRUE;
}

/**
 * Generate a CGA and parameters
 */
static int cga()
{
	certificate_t *cert = NULL;
	public_key_t *public = NULL;
	char *file = NULL, *error = NULL, *arg;
	chunk_t prefix = chunk_empty, encoding = chunk_empty, chunk;
	int sec = 0;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				goto usage;
			case 'i':
				file = arg;
				continue;
			case 's':
				sec = atoi(arg);
				continue;
			case 'p':
				if (!make_prefix(arg, &prefix))
				{
					error = "invalid --prefix";
					goto usage;
				}
				continue;
			case EOF:
				break;
			default:
				error = "invalid --cga option";
				goto usage;
		}
		break;
	}

	if (!prefix.len)
	{
		error = "--prefix is required";
		goto usage;
	}

	DBG2(DBG_LIB, "Reading public key:");
	if (file)
	{
		public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
									BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		if (!chunk_from_fd(0, &chunk))
		{
			fprintf(stderr, "%s: ", strerror(errno));
			error = "reading public key failed";
			goto end;
		}
		public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
									 BUILD_BLOB, chunk, BUILD_END);
		free(chunk.ptr);
	}

	if (!public)
	{
		error = "parsing public key failed";
		goto end;
	}

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_CGA_PARAMS,
							  BUILD_PUBLIC_KEY, public, BUILD_CGA_SEC, sec,
							  BUILD_CGA_PREFIX, prefix, BUILD_END);
	if (!cert)
	{
		error = "generating CGA parameters failed";
		goto end;
	}
	if (!cert->get_encoding(cert, CERT_CGA_ENCODING, &encoding))
	{
		error = "encoding CGA parameters failed";
		goto end;
	}
	set_file_mode(stdout, CERT_CGA_ENCODING);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		error = "writing CGA parameters key failed";
		goto end;
	}
	fprintf(stderr, "%Y\n", cert->get_subject(cert));

end:
	DESTROY_IF(cert);
	DESTROY_IF(public);
	free(encoding.ptr);
	free(prefix.ptr);

	if (error)
	{
		fprintf(stderr, "%s\n", error);
		return 1;
	}
	return 0;

usage:
	free(prefix.ptr);
	return command_usage(error);
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		cga, '6', "cga",
		"generate an IPv6 CGA for a public key and prefix",
		{"[--in file] --prefix prefix [--sec Sec]"},
		{
			{"help",			'h', 0, "show usage information"},
			{"in",				'i', 1, "public key to generate CGA for, default: stdin"},
			{"prefix",			'p', 1, "CGA /64 address prefix as IPv6 address"},
			{"sec",				's', 1, "CGA Sec brute force difficulty, 0-7"},
		}
	});
}
