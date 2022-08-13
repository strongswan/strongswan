/*
 * Copyright (C) 2022 Andreas Steffen, strongSec GmbH
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
#include "pki_cert.h"
#include "est/est.h"

#include <credentials/containers/pkcs7.h>
#include <credentials/certificates/certificate.h>
#include <credentials/sets/mem_cred.h>

/**
 * Get CA certificate[s] from an EST server (RFC 7030)
 */
static int estca()
{
	cred_encoding_type_t form = CERT_ASN1_DER;
	chunk_t est_response = chunk_empty;
	char *arg, *url = NULL, *caout = NULL;
	bool force = FALSE, success;
	u_int http_code = 0;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'u':
				url = arg;
				continue;
			case 'c':
				caout = arg;
				continue;
			case 'f':
				if (!get_form(arg, &form, CRED_CERTIFICATE))
				{
					return command_usage("invalid certificate output format");
				}
				continue;
			case 'F':
				force = TRUE;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --estca option");
		}
		break;
	}

	if (!url)
	{
		return command_usage("--url is required");
	}

	if (!est_https_request(url, EST_CACERTS, FALSE, chunk_empty, &est_response,
						   &http_code))
	{
		DBG1(DBG_APP, "did not receive a valid EST response: HTTP %u", http_code);
		return 1;
	}
	success = pki_cert_extract_cacerts(est_response, caout, NULL, TRUE, form,
									   force);
	chunk_free(&est_response);

	return success ? 0 : 1;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		estca, 'e', "estca",
		"get CA certificate[s] from a EST server",
		{"--url url [--caout file] [--outform der|pem] [--force]"},
		{
			{"help",    'h', 0, "show usage information"},
			{"url",     'u', 1, "URL of the SCEP server"},
			{"caout",   'c', 1, "CA certificate [template]"},
			{"outform", 'f', 1, "encoding of stored certificates, default: der"},
			{"force",   'F', 0, "force overwrite of existing files"},
		}
	});
}
