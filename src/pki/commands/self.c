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

#include <utils/linked_list.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

/**
 * Create a self signed certificate.
 */
static int self()
{
	key_type_t type = KEY_RSA;
	hash_algorithm_t digest = HASH_SHA1;
	certificate_t *cert = NULL;
	private_key_t *private = NULL;
	public_key_t *public = NULL;
	char *file = NULL, *dn = NULL, *hex = NULL, *error = NULL;
	identification_t *id = NULL;
	linked_list_t *san, *ocsp;
	int lifetime = 1080;
	chunk_t serial = chunk_empty;
	chunk_t encoding = chunk_empty;
	time_t not_before, not_after;
	x509_flag_t flags = 0;
	char *arg;

	san = linked_list_create();
	ocsp = linked_list_create();

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				goto usage;
			case 't':
				if (streq(arg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(arg, "ecdsa"))
				{
					type = KEY_ECDSA;
				}
				else
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
			case 'o':
				ocsp->insert_last(ocsp, arg);
				continue;
			case EOF:
				break;
			default:
				error = "invalid --self option";
				goto usage;
		}
		break;
	}

	if (!dn)
	{
		error = "--dn is required";
		goto usage;
	}
	id = identification_create_from_string(dn);
	if (id->get_type(id) != ID_DER_ASN1_DN)
	{
		error = "supplied --dn is not a distinguished name";
		goto end;
	}
	if (file)
	{
		private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
									 BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
									 BUILD_FROM_FD, 0, BUILD_END);
	}
	if (!private)
	{
		error = "parsing private key failed";
		goto end;
	}
	public = private->get_public_key(private);
	if (!public)
	{
		error = "extracting public key failed";
		goto end;
	}
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
		rng->destroy(rng);
	}
	not_before = time(NULL);
	not_after = not_before + lifetime * 24 * 60 * 60;
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
						BUILD_SIGNING_KEY, private, BUILD_PUBLIC_KEY, public,
						BUILD_SUBJECT, id, BUILD_NOT_BEFORE_TIME, not_before,
						BUILD_NOT_AFTER_TIME, not_after, BUILD_SERIAL, serial,
						BUILD_DIGEST_ALG, digest, BUILD_X509_FLAG, flags,
						BUILD_SUBJECT_ALTNAMES, san,
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
	DESTROY_IF(cert);
	DESTROY_IF(public);
	DESTROY_IF(private);
	san->destroy_offset(san, offsetof(identification_t, destroy));
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
	ocsp->destroy(ocsp);
	return command_usage(error);
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		self, 's', "self",
		"create a self signed certificate",
		{"[--in file] [--type rsa|ecdsa]",
		 " --dn distinguished-name [--san subjectAltName]+",
		 "[--lifetime days] [--serial hex] [--ca] [--ocsp uri]+",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "private key input file, default: stdin"},
			{"type",	't', 1, "type of input key, default: rsa"},
			{"dn",		'd', 1, "subject and issuer distinguished name"},
			{"san",		'a', 1, "subjectAltName to include in certificate"},
			{"lifetime",'l', 1, "days the certificate is valid, default: 1080"},
			{"serial",	's', 1, "serial number in hex, default: random"},
			{"ca",		'b', 0, "include CA basicConstraint, default: no"},
			{"ocsp",	'o', 1, "OCSP AuthorityInfoAccess URI to include"},
			{"digest",	'g', 1, "digest for signature creation, default: sha1"},
		}
	});
}
