/*
 * Copyright (C) 2005 Jan Hutter, Martin Willi
 * Copyright (C) 2012 Tobias Brunner
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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "pki.h"
#include "scep/scep.h"

#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>
#include <credentials/sets/mem_cred.h>


typedef enum {
	CERT_TYPE_ROOT_CA,
	CERT_TYPE_SUB_CA,
	CERT_TYPE_RA
} cert_type_t;

static char *cert_type_label[] = { "Root CA", "Sub CA", "RA" };

/**
 * Determine certificate type based on X.509 certificate flags
 */
static cert_type_t get_cert_type(certificate_t *cert)
{
	x509_t *x509;
	x509_flag_t flags;

	x509 = (x509_t*)cert;
	flags = x509->get_flags(x509);

	if (flags & X509_CA)
	{
		if (flags & X509_SELF_SIGNED)
		{
			return CERT_TYPE_ROOT_CA;
		}
		else
		{
			return CERT_TYPE_SUB_CA;
		}
	}
	else
	{
		return CERT_TYPE_RA;
	}
}

/**
 * Output cert type, subject as well as SHA256 and SHA1 fingerprints
 */
static bool print_cert_info(certificate_t *cert, cert_type_t cert_type)
{
	hasher_t *hasher = NULL;
	char digest_buf[HASH_SIZE_SHA256];
	char base64_buf[HASH_SIZE_SHA256];
	chunk_t cert_digest = {digest_buf, HASH_SIZE_SHA256};
	chunk_t cert_id, encoding = chunk_empty;
	bool success = FALSE;

	DBG1(DBG_APP, "%s cert \"%Y\"", cert_type_label[cert_type],
									cert->get_subject(cert));

	if (!cert->get_encoding(cert, CERT_ASN1_DER, &encoding))
	{
		DBG1(DBG_APP, "could not get certificate encoding");
		return FALSE;
	}

	/* SHA256 certificate digest */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA256);
	if (!hasher)
	{
		DBG1(DBG_APP, "could not create SHA256 hasher");
		goto end;
	}
	if (!hasher->get_hash(hasher, encoding, digest_buf))
	{
		DBG1(DBG_APP, "could not compute SHA256 hash");
		goto end;
	}
	hasher->destroy(hasher);

	DBG1(DBG_APP, "  SHA256: %#B", &cert_digest);

	/* SHA1 certificate digest */
	hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
	if (!hasher)
	{
		DBG1(DBG_APP, "could not create SHA1 hasher");
		goto end;
	}
	if (!hasher->get_hash(hasher, encoding, digest_buf))
	{
		DBG1(DBG_APP, "could not compute SHA1 hash");
		goto end;
	}
	cert_digest.len = HASH_SIZE_SHA1;
	cert_id = chunk_to_base64(cert_digest, base64_buf);

	DBG1(DBG_APP, "  SHA1  : %#B (%.*s)", &cert_digest,
										   cert_id.len-1, cert_id.ptr);
	success = TRUE;

end:
	DESTROY_IF(hasher);
	chunk_free(&encoding);

	return success;
}

static bool build_pathname(char **path, cert_type_t cert_type, int *cert_type_count,
						   char *caout, char *raout, cred_encoding_type_t form)
{
	char *basename, *extension, *dot, *suffix;
	int  count, len;
	bool number;

	basename = caout;
	extension = "";
	suffix = (form == CERT_ASN1_DER) ? "der" : "pem";

	count = cert_type_count[cert_type];
	number = count > 1;

	switch (cert_type)
	{
		default:
		case CERT_TYPE_ROOT_CA:
			if (count > 1)
			{
				extension = "-root";
			}
			break;
		case CERT_TYPE_SUB_CA:
			number = TRUE;
			break;
		case CERT_TYPE_RA:
			if (raout)
			{
				basename = raout;
			}
			else
			{
				extension = "-ra";
			}
			break;
	}

	/* skip if no path is defined */
	if (!basename)
	{
		*path = NULL;
		return TRUE;
	}

	/* check for a file suffix */
	dot = strrchr(basename, '.');
	len = dot ? (dot - basename) : strlen(basename);
	if (dot && (dot[1] != '\0'))
	{
		suffix = dot + 1;
	}

	if (number)
	{
		return asprintf(path, "%.*s%s-%d.%s", len, basename, extension,
						count, suffix) > 0;
	}
	else
	{
		return asprintf(path, "%.*s%s.%s", len, basename, extension, suffix) > 0;
	}
}

/**
 * Writo CA/RA certificate to file in DER or PEM format
 */
static bool write_cert(certificate_t *cert, cert_type_t cert_type, bool trusted,
					   char *path, cred_encoding_type_t form, bool force)
{
	chunk_t encoding = chunk_empty;
	time_t until;
	bool written, valid;

	if (path)
	{
		if (!cert->get_encoding(cert, form, &encoding))
		{
			DBG1(DBG_APP, "could not get certificate encoding");
			return FALSE;
		}

		written = chunk_write(encoding, path, 0022, force);
		chunk_free(&encoding);

		if (!written)
		{
			DBG1(DBG_APP, "could not write cert file '%s': %s",
				 path, strerror(errno));
			return FALSE;
		}
	}
	valid = cert->get_validity(cert, NULL, NULL, &until);
	DBG1(DBG_APP, "%s cert is %strusted, %s %T, %s'%s'",
		 cert_type_label[cert_type], trusted ? "" : "un",
		 valid ? "valid until" : "invalid since", &until, FALSE,
		 path ? "written to " : "", path ? path : "not written");

	return TRUE;
}

/**
 * Get CA certificate[s] from a SCEP server (RFC 8894)
 */
static int scepca()
{
	cred_encoding_type_t form = CERT_ASN1_DER;
	chunk_t scep_response = chunk_empty;
	mem_cred_t *creds = NULL;
	certificate_t *cert;
	cert_type_t cert_type;
	pkcs7_t *pkcs7 = NULL;
	bool force = FALSE, written = FALSE;
	char *arg, *url = NULL, *caout = NULL, *raout = NULL, *path = NULL;
	int status = 1;

	int cert_type_count[] = { 0, 0, 0 };

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
			case 'r':
				raout = arg;
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
				return command_usage("invalid --scepca option");
		}
		break;
	}

	if (!url)
	{
		return command_usage("--url is required");
	}

	if (!scep_http_request(url, chunk_empty, SCEP_GET_CA_CERT, FALSE,
						   &scep_response))
	{
		DBG1(DBG_APP, "did not receive a valid scep response");
		return 1;
	}

	creds = mem_cred_create();
	lib->credmgr->add_set(lib->credmgr, &creds->set);

	pkcs7 = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PKCS7,
							BUILD_BLOB_ASN1_DER, scep_response, BUILD_END);
	if (!pkcs7)
	{	/* no PKCS#7 encoded CA+RA certificates, assume single root CA cert */

		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB, scep_response, BUILD_END);
		if (!cert)
		{
			DBG1(DBG_APP, "could not parse single CA certificate");
			goto end;
		}
		cert_type = get_cert_type(cert);
		cert_type_count[cert_type]++;

		if (print_cert_info(cert, cert_type) &&
			build_pathname(&path, cert_type, cert_type_count, caout, raout, form))
		{
			written = write_cert(cert, cert_type, FALSE, path, form, force);
		}
	}
	else
	{
		enumerator_t *enumerator;

		enumerator = pkcs7->create_cert_enumerator(pkcs7);
		while (enumerator->enumerate(enumerator, &cert))
		{
			cert_type = get_cert_type(cert);
			if (cert_type == CERT_TYPE_ROOT_CA)
			{
				/* trust in root CA has to be established manuallly */
				creds->add_cert(creds, TRUE, cert->get_ref(cert));

				cert_type_count[cert_type]++;

				if (!print_cert_info(cert, cert_type))
				{
					goto end;
				}
				if (build_pathname(&path, cert_type, cert_type_count,
								   caout, raout, form))
				{
					written = write_cert(cert, cert_type, FALSE, path, form, force);
					free(path);
				}
				if (!written)
				{
					break;
				}
			}
			else
			{
				/* trust relative to root CA will be established in round 2 */
				creds->add_cert(creds, FALSE, cert->get_ref(cert));
			}
		}
		enumerator->destroy(enumerator);

		if (!written)
		{
			goto end;
		}

		enumerator = pkcs7->create_cert_enumerator(pkcs7);
		while (enumerator->enumerate(enumerator, &cert))
		{
			written = FALSE;

			cert_type = get_cert_type(cert);
			if (cert_type != CERT_TYPE_ROOT_CA)
			{
				enumerator_t *certs;
				bool trusted;

				if (!print_cert_info(cert, cert_type))
				{
					break;
				}

				/* establish trust relativ to root CA */
				certs = lib->credmgr->create_trusted_enumerator(lib->credmgr,
									KEY_RSA, cert->get_subject(cert), FALSE);
				trusted = certs->enumerate(certs, &cert, NULL);
				certs->destroy(certs);

				cert_type_count[cert_type]++;

				if (build_pathname(&path, cert_type, cert_type_count,
								    caout, raout, form))
				{
					written = write_cert(cert, cert_type, trusted, path, form, force);
					free(path);
				}
				if (!written)
				{
					break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}
	status = written ? 0 : 1;

end:
	/* cleanup */
	lib->credmgr->remove_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	free(scep_response.ptr);
	if (pkcs7)
	{
		container_t *container = &pkcs7->container;

		container->destroy(container);
	}

	return status;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		scepca, 'C', "scepca",
		"get CA [and RA] certificate[s] from a SCEP server",
		{"--url url [--caout file] [--raout file] [--outform der|pem] [--force]"},
		{
			{"help",    'h', 0, "show usage information"},
			{"url",     'u', 1, "URL of the SCEP server"},
			{"caout",   'c', 1, "CA certificate [template]"},
			{"raout",   'r', 1, "RA certificate [template]"},
			{"outform", 'f', 1, "encoding of stored certificates, default: der"},
			{"force",   'F', 0, "force overwrite of existing files"},
		}
	});
}
