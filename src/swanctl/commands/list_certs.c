/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
 *
 * Copyright (C) 2015 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/certificate_printer.h>
#include <selectors/traffic_selector.h>

#include <vici_version.h>
#include <vici_cert_info.h>

#include "command.h"

/**
 * Current certificate type info
 */
static vici_cert_info_t *current_cert_info = NULL;

/**
 * Print PEM encoding of a certificate
 */
static void print_pem(certificate_t *cert)
{
	chunk_t encoding;

	if (cert->get_encoding(cert, CERT_PEM, &encoding))
	{
		printf("%.*s", (int)encoding.len, encoding.ptr);
		free(encoding.ptr);
	}
	else
	{
		fprintf(stderr, "PEM encoding certificate failed\n");
	}
}

CALLBACK(list_cb, void,
	command_format_options_t *format, char *name, vici_res_t *res)
{
	certificate_t *cert;
	certificate_printer_t *printer;
	vici_version_t version;
	vici_cert_info_t *cert_info;
	bool detailed, utc, has_privkey, first = FALSE;
	char *version_str, *type_str;
	void *buf;
	int len;

	if (*format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "list-cert event", *format & COMMAND_FORMAT_PRETTY,
				  stdout);
		return;
	}

	version_str = vici_find_str(res, "1.0", "vici");
	if (!enum_from_name(vici_version_names, version_str, &version) ||
		version == VICI_1_0)
	{
		fprintf(stderr, "unsupported vici version '%s'\n", version_str);
		return;
	}

	buf = vici_find(res, &len, "data");
	if (!buf)
	{
		fprintf(stderr, "received incomplete certificate data\n");
		return;
	}
	has_privkey = streq(vici_find_str(res, "no", "has_privkey"), "yes");

	type_str = vici_find_str(res, "any", "type");
	cert_info = vici_cert_info_retrieve(type_str);
	if (!cert_info || cert_info->type == CERT_ANY)
	{
		fprintf(stderr, "unsupported certificate type '%s'\n", type_str);
		return;
	}

	/* Detect change of certificate type */
	if (cert_info != current_cert_info)
	{
		first = TRUE;
		current_cert_info = cert_info;
	}

	/* Parse certificate data blob */
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, cert_info->type,
							  BUILD_BLOB_ASN1_DER, chunk_create(buf, len),
							  BUILD_END);
	if (cert)
	{
		if (*format & COMMAND_FORMAT_PEM)
		{
			print_pem(cert);
		}
		else
		{
			if (first)
			{
				printf("\nList of %ss:\n", cert_info->caption);
			}
			printf("\n");
			detailed = !(*format & COMMAND_FORMAT_SHORT);
			utc = *format & COMMAND_FORMAT_UTC;
			printer = certificate_printer_create(stdout, detailed, utc);
			printer->print(printer, cert, has_privkey);
			printer->destroy(printer);
		}
		cert->destroy(cert);
	}
	else
	{
		fprintf(stderr, "parsing certificate failed\n");
	}
}

static int list_certs(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	command_format_options_t format = COMMAND_FORMAT_NONE;
	char *arg, *subject = NULL, *type = NULL;
	int ret;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 's':
				subject = arg;
				continue;
			case 't':
				type = arg;
				continue;
			case 'p':
				format |= COMMAND_FORMAT_PEM;
				continue;
			case 'P':
				format |= COMMAND_FORMAT_PRETTY;
				/* fall through to raw */
			case 'r':
				format |= COMMAND_FORMAT_RAW;
				continue;
			case 'S':
				format |= COMMAND_FORMAT_SHORT;
				continue;
			case 'U':
				format |= COMMAND_FORMAT_UTC;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --list-certs option");
		}
		break;
	}
	if (vici_register(conn, "list-cert", list_cb, &format) != 0)
	{
		ret = errno;
		fprintf(stderr, "registering for certificates failed: %s\n",
				strerror(errno));
		return ret;
	}
	req = vici_begin("list-certs");
	vici_add_version(req, VICI_VERSION);

	if (type)
	{
		vici_add_key_valuef(req, "type", "%s", type);
	}
	if (subject)
	{
		vici_add_key_valuef(req, "subject", "%s", subject);
	}

	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "list-certs request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "list-certs reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	vici_free_res(res);
	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		list_certs, 'x', "list-certs", "list stored certificates",
		{"[--subject <dn/san>] "
		 "[--type x509|x509ca|x509aa|x509ac|x509crl|x509ocsp|ocsp] "
		 "[--pem] [--raw|--pretty|--short|--utc]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"subject",		's', 1, "filter by certificate subject"},
			{"type",		't', 1, "filter by certificate type"},
			{"pem",			'p', 0, "print PEM encoding of certificate"},
			{"raw",			'r', 0, "dump raw response message"},
			{"pretty",		'P', 0, "dump raw response message in pretty print"},
			{"short",		'S', 0, "omit some certificate details"},
			{"utc",			'U', 0, "use UTC for time fields"},
		}
	});
}
