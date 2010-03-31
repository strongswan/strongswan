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

#include <time.h>

#include "pki.h"

#include <debug.h>
#include <utils/linked_list.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/pkcs10.h>

/**
 * Issue a certificate using a CA certificate and key
 */
static int issue()
{
	hash_algorithm_t digest = HASH_SHA1;
	certificate_t *cert_req = NULL, *cert = NULL, *ca =NULL;
	private_key_t *private = NULL;
	public_key_t *public = NULL;
	bool pkcs10 = FALSE;
	char *file = NULL, *dn = NULL, *hex = NULL, *cacert = NULL, *cakey = NULL;
	char *error = NULL;
	identification_t *id = NULL;
	linked_list_t *san, *cdps, *ocsp;
	int lifetime = 1080;
	int pathlen = X509_NO_PATH_LEN_CONSTRAINT;
	chunk_t serial = chunk_empty;
	chunk_t encoding = chunk_empty;
	time_t not_before, not_after;
	x509_flag_t flags = 0;
	x509_t *x509;
	char *arg;

	san = linked_list_create();
	cdps = linked_list_create();
	ocsp = linked_list_create();

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				goto usage;
			case 't':
				if (streq(arg, "pkcs10"))
				{
					pkcs10 = TRUE;
				}
				else if (!streq(arg, "pub"))
				{
					error = "invalid input type";
					goto usage;
				}
				continue;
			case 'g':
				digest = get_digest(arg);
				if (digest == HASH_UNKNOWN)
				{
					error = "invalid --digest type";
					goto usage;
				}
				continue;
			case 'i':
				file = arg;
				continue;
			case 'c':
				cacert = arg;
				continue;
			case 'k':
				cakey = arg;
				continue;
			case 'd':
				dn = arg;
				continue;
			case 'a':
				san->insert_last(san, identification_create_from_string(arg));
				continue;
			case 'l':
				lifetime = atoi(arg);
				if (!lifetime)
				{
					error = "invalid --lifetime value";
					goto usage;
				}
				continue;
			case 's':
				hex = arg;
				continue;
			case 'b':
				flags |= X509_CA;
				continue;
			case 'p':
				pathlen = atoi(arg);
				continue;
			case 'f':
				if (streq(arg, "serverAuth"))
				{
					flags |= X509_SERVER_AUTH;
				}
				else if (streq(arg, "clientAuth"))
				{
					flags |= X509_CLIENT_AUTH;
				}
				else if (streq(arg, "ocspSigning"))
				{
					flags |= X509_OCSP_SIGNER;
				}
				continue;
			case 'u':
				cdps->insert_last(cdps, arg);
				continue;
			case 'o':
				ocsp->insert_last(ocsp, arg);
				continue;
			case EOF:
				break;
			default:
				error = "invalid --issue option";
				goto usage;
		}
		break;
	}

	if (!pkcs10 && !dn)
	{
		error = "--dn is required";
		goto usage;
	}
	if (!cacert)
	{
		error = "--cacert is required";
		goto usage;
	}
	if (!cakey)
	{
		error = "--cakey is required";
		goto usage;
	}
	if (dn)
	{
		id = identification_create_from_string(dn);
		if (id->get_type(id) != ID_DER_ASN1_DN)
		{
			error = "supplied --dn is not a distinguished name";
			goto end;
		}
	}

	DBG2(DBG_LIB, "Reading ca certificate:");
	ca = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							BUILD_FROM_FILE, cacert, BUILD_END);
	if (!ca)
	{
		error = "parsing CA certificate failed";
		goto end;
	}
	x509 = (x509_t*)ca;
	if (!(x509->get_flags(x509) & X509_CA))
	{
		error = "CA certificate misses CA basicConstraint";
		goto end;
	}
	public = ca->get_public_key(ca);
	if (!public)
	{
		error = "extracting CA certificate public key failed";
		goto end;
	}

	DBG2(DBG_LIB, "Reading ca private key:");
	private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY,
								 public->get_type(public),
								 BUILD_FROM_FILE, cakey, BUILD_END);
	if (!private)
	{
		error = "parsing CA private key failed";
		goto end;
	}
	if (!private->belongs_to(private, public))
	{
		error = "CA private key does not match CA certificate";
		goto end;
	}
	public->destroy(public);

	if (hex)
	{
		serial = chunk_from_hex(chunk_create(hex, strlen(hex)), NULL);
	}
	else
	{
		rng_t *rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);

		if (!rng)
		{
			error = "no random number generator found";
			goto end;
		}
		rng->allocate_bytes(rng, 8, &serial);
		while (*serial.ptr == 0x00)
		{
			/* we don't accept a serial number with leading zeroes */
			rng->get_bytes(rng, 1, serial.ptr);
		}
		rng->destroy(rng);
	}

	if (pkcs10)
	{
		enumerator_t *enumerator;
		identification_t *subjectAltName;
		pkcs10_t *req;

		DBG2(DBG_LIB, "Reading certificate request");
		if (file)
		{
			cert_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
										  CERT_PKCS10_REQUEST,
										  BUILD_FROM_FILE, file, BUILD_END);
		}
		else
		{
			cert_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
										  CERT_PKCS10_REQUEST,
										  BUILD_FROM_FD, 0, BUILD_END);
		}
		if (!cert_req)
		{
			error = "parsing certificate request failed";
			goto end;
		}

		/* If not set yet use subject from PKCS#10 certificate request as DN */
		if (!id)
		{
			id = cert_req->get_subject(cert_req);
			id = id->clone(id);
		}

		/* Add subjectAltNames from PKCS#10 certificate request */
		req = (pkcs10_t*)cert_req;
		enumerator = req->create_subjectAltName_enumerator(req);
		while (enumerator->enumerate(enumerator, &subjectAltName))
		{
			san->insert_last(san, subjectAltName->clone(subjectAltName));
		}
		enumerator->destroy(enumerator);

		/* Use public key from PKCS#10 certificate request */
		public = cert_req->get_public_key(cert_req);
	}
	else
	{
		DBG2(DBG_LIB, "Reading public key:");
		if (file)
		{
			public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
										BUILD_FROM_FILE, file, BUILD_END);
		}
		else
		{
			public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
										 BUILD_FROM_FD, 0, BUILD_END);
		}
	}
	if (!public)
	{
		error = "parsing public key failed";
		goto end;
	}

	not_before = time(NULL);
	not_after = not_before + lifetime * 24 * 60 * 60;

	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
					BUILD_SIGNING_KEY, private, BUILD_SIGNING_CERT, ca,
					BUILD_PUBLIC_KEY, public, BUILD_SUBJECT, id,
					BUILD_NOT_BEFORE_TIME, not_before, BUILD_DIGEST_ALG, digest,
					BUILD_NOT_AFTER_TIME, not_after, BUILD_SERIAL, serial,
					BUILD_SUBJECT_ALTNAMES, san, BUILD_X509_FLAG, flags,
					BUILD_PATHLEN, pathlen,
					BUILD_CRL_DISTRIBUTION_POINTS, cdps,
					BUILD_OCSP_ACCESS_LOCATIONS, ocsp, BUILD_END);
	if (!cert)
	{
		error = "generating certificate failed";
		goto end;
	}
	encoding = cert->get_encoding(cert);
	if (!encoding.ptr)
	{
		error = "encoding certificate failed";
		goto end;
	}
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		error = "writing certificate key failed";
		goto end;
	}

end:
	DESTROY_IF(id);
	DESTROY_IF(cert_req);
	DESTROY_IF(cert);
	DESTROY_IF(ca);
	DESTROY_IF(public);
	DESTROY_IF(private);
	san->destroy_offset(san, offsetof(identification_t, destroy));
	cdps->destroy(cdps);
	ocsp->destroy(ocsp);
	free(encoding.ptr);
	free(serial.ptr);

	if (error)
	{
		fprintf(stderr, "%s\n", error);
		return 1;
	}
	return 0;

usage:
	san->destroy_offset(san, offsetof(identification_t, destroy));
	cdps->destroy(cdps);
	ocsp->destroy(ocsp);
	return command_usage(error);
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		issue, 'i', "issue",
		"issue a certificate using a CA certificate and key",
		{"[--in file] [--type pub|pkcs10]",
		 " --cacert file --cakey file --dn subject-dn [--san subjectAltName]+",
		 "[--lifetime days] [--serial hex] [--crl uri]+ [--ocsp uri]+",
		 "[--ca] [--pathlen len] [--flag serverAuth|clientAuth|ocspSigning]+",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "public key/request file to issue, default: stdin"},
			{"type",	't', 1, "type of input, default: pub"},
			{"cacert",	'c', 1, "CA certificate file"},
			{"cakey",	'k', 1, "CA private key file"},
			{"dn",		'd', 1, "distinguished name to include as subject"},
			{"san",		'a', 1, "subjectAltName to include in certificate"},
			{"lifetime",'l', 1, "days the certificate is valid, default: 1080"},
			{"serial",	's', 1, "serial number in hex, default: random"},
			{"ca",		'b', 0, "include CA basicConstraint, default: no"},
			{"pathlen",	'p', 1, "set path length constraint"},
			{"flag",	'f', 1, "include extendedKeyUsage flag"},
			{"crl",		'u', 1, "CRL distribution point URI to include"},
			{"ocsp",	'o', 1, "OCSP AuthorityInfoAccess URI to include"},
			{"digest",	'g', 1, "digest for signature creation, default: sha1"},
		}
	});
}

