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
#include <utils/optionsfrom.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

/**
 * Issue a certificate using a CA certificate and key
 */
static int issue(int argc, char *argv[])
{
	hash_algorithm_t digest = HASH_SHA1;
	certificate_t *cert = NULL, *ca =NULL;
	private_key_t *private = NULL;
	public_key_t *public = NULL;
	char *file = NULL, *dn = NULL, *hex = NULL, *cacert = NULL, *cakey = NULL;
	char *error = NULL;
	identification_t *id = NULL;
	linked_list_t *san;
	int lifetime = 1080;
	chunk_t serial = chunk_empty;
	chunk_t encoding = chunk_empty;
	time_t not_before, not_after;
	x509_flag_t flags = 0;
	x509_t *x509;
	options_t *options;

	options = options_create();
	san = linked_list_create();

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", command_opts, NULL))
		{
			case 'h':
				goto usage;
			case '+':
				if (!options->from(options, optarg, &argc, &argv, optind))
				{
					error = "invalid options file";
					goto usage;
				}
				continue;
			case 't':
				if (!streq(optarg, "pub"))
				{
					error = "invalid input type";
					goto usage;
				}
				continue;
			case 'g':
				digest = get_digest(optarg);
				if (digest == HASH_UNKNOWN)
				{
					error = "invalid --digest type";
					goto usage;
				}
				continue;
			case 'i':
				file = optarg;
				continue;
			case 'c':
				cacert = optarg;
				continue;
			case 'k':
				cakey = optarg;
				continue;
			case 'd':
				dn = optarg;
				continue;
			case 'a':
				san->insert_last(san, identification_create_from_string(optarg));
				continue;
			case 'l':
				lifetime = atoi(optarg);
				if (!lifetime)
				{
					error = "invalid --lifetime value";
					goto usage;
				}
				continue;
			case 's':
				hex = optarg;
				continue;
			case 'b':
				flags |= X509_CA;
				continue;
			case EOF:
				break;
			default:
				error = "invalid --issue option";
				goto usage;
		}
		break;
	}

	if (!dn)
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
	id = identification_create_from_string(dn);
	if (id->get_type(id) != ID_DER_ASN1_DN)
	{
		error = "supplied --dn is not a distinguished name";
		goto end;
	}
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
	if (!public)
	{
		error = "parsing public key failed";
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
					BUILD_SIGNING_KEY, private, BUILD_SIGNING_CERT, ca,
					BUILD_PUBLIC_KEY, public, BUILD_SUBJECT, id,
					BUILD_NOT_BEFORE_TIME, not_before, BUILD_DIGEST_ALG, digest,
					BUILD_NOT_AFTER_TIME, not_after, BUILD_SERIAL, serial,
					BUILD_SUBJECT_ALTNAMES, san, BUILD_X509_FLAG, flags,
					BUILD_END);
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
	DESTROY_IF(ca);
	DESTROY_IF(public);
	DESTROY_IF(private);
	san->destroy_offset(san, offsetof(identification_t, destroy));
	options->destroy(options);
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
	options->destroy(options);
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
		 " --cacert file --cakey file",
		 " --dn subject-dn [--san subjectAltName]+",
		 "[--lifetime days] [--serial hex] [--ca]",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512]",
		 "[--options file]"},
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
			{"digest",	'g', 1, "digest for signature creation, default: sha1"},
			{"options",	'+', 1, "read command line options from file"},
		}
	});
}

