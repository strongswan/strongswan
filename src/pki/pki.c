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

#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include <library.h>
#include <utils/linked_list.h>
#include <utils/optionsfrom.h>
#include <credentials/keys/private_key.h>
#include <credentials/certificates/certificate.h>
#include <credentials/certificates/x509.h>

static int help(int argc, char *argv[]);
static int gen(int argc, char *argv[]);
static int pub(int argc, char *argv[]);
static int keyid(int argc, char *argv[]);
static int self(int argc, char *argv[]);
static int issue(int argc, char *argv[]);
static int verify(int argc, char *argv[]);

typedef enum {
	CMD_HELP = 0,
	CMD_GEN,
	CMD_PUB,
	CMD_KEYID,
	CMD_SELF,
	CMD_ISSUE,
	CMD_VERIFY,
	CMD_MAX
} cmd_t;

#define MAX_OPTIONS 14

static struct {
	int (*call)(int, char*[]);
	char op;
	char *cmd;
	char *description;
	char *line[8];
	struct {
		char *name;
		char op;
		int arg;
		char *desc;
	} options[MAX_OPTIONS];
} cmds[] = {
	[CMD_HELP] = { help, 'h', "help",
		"show usage information"
	},
	[CMD_GEN] = { gen, 'g', "gen", "generate a new private key",
		{"[--type rsa|ecdsa] [--size bits] [--outform der|pem|pgp]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"type",	't', 1, "type of key, default: rsa"},
			{"size",	's', 1, "keylength in bits, default: rsa 2048, ecdsa 384"},
			{"outform",	'f', 1, "encoding of generated private key"},
		}
	},
	[CMD_PUB] = { pub, 'p', "pub",
		"extract the public key from a private key/certificate",
		{"[--in file] [--type rsa|ecdsa|x509] [--outform der|pem|pgp]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"type",	't', 1, "type of credential, default: rsa"},
			{"outform",	'f', 1, "encoding of extracted public key"},
		}
	},
	[CMD_KEYID] = { keyid, 'k', "keyid",
		"calculate key identifiers of a key/certificate",
		{"[--in file] [--type rsa-priv|ecdsa-priv|pub|x509]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"type",	't', 1, "type of key, default: rsa-priv"},
		}
	},
	[CMD_SELF] = { self, 's', "self",
		"create a self signed certificate",
		{"[--in file] [--type rsa|ecdsa]",
		 " --dn distinguished-name [--san subjectAltName]+",
		 "[--lifetime days] [--serial hex] [--ca]",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512]",
		 "[--options file]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "private key input file, default: stdin"},
			{"type",	't', 1, "type of input key, default: rsa"},
			{"dn",		'd', 1, "subject and issuer distinguished name"},
			{"san",		'a', 1, "subjectAltName to include in certificate"},
			{"lifetime",'l', 1, "days the certificate is valid, default: 1080"},
			{"serial",	's', 1, "serial number in hex, default: random"},
			{"ca",		'b', 0, "include CA basicConstraint, default: no"},
			{"digest",	'g', 1, "digest for signature creation, default: sha1"},
			{"options",	'+', 1, "read command line options from file"},
		}
	},
	[CMD_ISSUE] = { issue, 'i', "issue",
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
	},
	[CMD_VERIFY] = { verify, 'v', "verify",
		"verify a certificate using the CA certificate",
		{"[--in file] [--ca file]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "x509 certifcate to verify, default: stdin"},
			{"cacert",	'c', 1, "CA certificate, default: verify self signed"},
		}
	},
};

/**
 * Global options used by all subcommands
 */
static struct option long_opts[countof(cmds) > MAX_OPTIONS ?: MAX_OPTIONS];

/**
 * Build long_opts for a specific command
 */
static void build_opts(cmd_t cmd)
{
	int i;

	memset(long_opts, 0, sizeof(long_opts));
	if (cmd == CMD_HELP)
	{
		for (i = 0; i < CMD_MAX; i++)
		{
			long_opts[i].name = cmds[i].cmd;
			long_opts[i].val = cmds[i].op;
		}
	}
	else
	{
		for (i = 0; cmds[cmd].options[i].name; i++)
		{
			long_opts[i].name = cmds[cmd].options[i].name;
			long_opts[i].has_arg = cmds[cmd].options[i].arg;
			long_opts[i].val = cmds[cmd].options[i].op;
		}
	}
}

/**
 * Print usage text, with an optional error
 */
static int usage(cmd_t cmd, char *error)
{
	FILE *out = stdout;
	int i;

	if (error)
	{
		out = stderr;
		fprintf(out, "Error: %s\n", error);
	}
	fprintf(out, "strongSwan %s PKI tool\n", VERSION);
	fprintf(out, "usage:\n");
	if (cmd == CMD_HELP)
	{
		for (i = 0; i < CMD_MAX; i++)
		{
			fprintf(out, "  pki --%-6s %s\n", cmds[i].cmd, cmds[i].description);
		}
	}
	else
	{
		for (i = 0; cmds[cmd].line[i]; i++)
		{
			if (i == 0)
			{
				fprintf(out, "  pki --%s %s\n", cmds[cmd].cmd, cmds[cmd].line[i]);
			}
			else
			{
				fprintf(out, "               %s\n", cmds[cmd].line[i]);
			}
		}
		for (i = 0; cmds[cmd].options[i].name; i++)
		{
			fprintf(out, "        --%-8s %s\n",
					cmds[cmd].options[i].name, cmds[cmd].options[i].desc);
		}
	}
	return error != NULL;
}

/**
 * Convert a form string to a encoding type
 */
static bool get_form(char *form, key_encoding_type_t *type, bool pub)
{
	if (streq(form, "der"))
	{
		/* der encoded keys usually contain the complete SubjectPublicKeyInfo */
		*type = pub ? KEY_PUB_SPKI_ASN1_DER : KEY_PRIV_ASN1_DER;
	}
	else if (streq(form, "pem"))
	{
		*type = pub ? KEY_PUB_PEM : KEY_PRIV_PEM;
	}
	else if (streq(form, "pgp"))
	{
		*type = pub ? KEY_PUB_PGP : KEY_PRIV_PGP;
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

/**
 * Convert a digest string to a hash algorithm
 */
static hash_algorithm_t get_digest(char *name)
{
	if (streq(name, "md5"))
	{
		return HASH_MD5;
	}
	if (streq(name, "sha1"))
	{
		return HASH_SHA1;
	}
	if (streq(name, "sha224"))
	{
		return HASH_SHA224;
	}
	if (streq(name, "sha256"))
	{
		return HASH_SHA256;
	}
	if (streq(name, "sha384"))
	{
		return HASH_SHA384;
	}
	if (streq(name, "sha512"))
	{
		return HASH_SHA512;
	}
	return HASH_UNKNOWN;
}

/**
 * Show usage information
 */
static int help(int argc, char *argv[])
{
	return usage(CMD_HELP, NULL);
}

/**
 * Generate a private key
 */
static int gen(int argc, char *argv[])
{
	key_encoding_type_t form = KEY_PRIV_ASN1_DER;
	key_type_t type = KEY_RSA;
	u_int size = 0;
	private_key_t *key;
	chunk_t encoding;

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case 'h':
				return usage(CMD_GEN, NULL);
			case 't':
				if (streq(optarg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa"))
				{
					type = KEY_ECDSA;
				}
				else
				{
					return usage(CMD_GEN, "invalid key type");
				}
				continue;
			case 'o':
				if (!get_form(optarg, &form, FALSE))
				{
					return usage(CMD_GEN, "invalid key output format");
				}
				continue;
			case 's':
				size = atoi(optarg);
				if (!size)
				{
					return usage(CMD_GEN, "invalid key size");
				}
				continue;
			case EOF:
				break;
			default:
				return usage(CMD_GEN, "invalid --gen option");
		}
		break;
	}
	/* default key sizes */
	if (!size)
	{
		switch (type)
		{
			case KEY_RSA:
				size = 2048;
				break;
			case KEY_ECDSA:
				size = 384;
				break;
			default:
				break;
		}
	}
	key = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
							 BUILD_KEY_SIZE, size, BUILD_END);
	if (!key)
	{
		fprintf(stderr, "private key generation failed\n");
		return 1;
	}
	if (!key->get_encoding(key, form, &encoding))
	{
		fprintf(stderr, "private key encoding failed\n");
		key->destroy(key);
		return 1;
	}
	key->destroy(key);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		fprintf(stderr, "writing private key failed\n");
		free(encoding.ptr);
		return 1;
	}
	free(encoding.ptr);
	return 0;
}

/**
 * Extract a public key from a private key/certificate
 */
static int pub(int argc, char *argv[])
{
	key_encoding_type_t form = KEY_PUB_SPKI_ASN1_DER;
	credential_type_t type = CRED_PRIVATE_KEY;
	int subtype = KEY_RSA;
	certificate_t *cert;
	private_key_t *private;
	public_key_t *public;
	chunk_t encoding;
	char *file = NULL;
	void *cred;

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case 'h':
				return usage(CMD_PUB, NULL);
			case 't':
				if (streq(optarg, "rsa"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_ECDSA;
				}
				else if (streq(optarg, "x509"))
				{
					type = CRED_CERTIFICATE;
					subtype = CERT_X509;
				}
				else
				{
					return usage(CMD_PUB, "invalid input type");
				}
				continue;
			case 'f':
				if (!get_form(optarg, &form, TRUE))
				{
					return usage(CMD_PUB, "invalid output format");
				}
				continue;
			case 'i':
				file = optarg;
				continue;
			case EOF:
				break;
			default:
				return usage(CMD_PUB, "invalid --pub option");
		}
		break;
	}
	if (file)
	{
		cred = lib->creds->create(lib->creds, type, subtype,
									 BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		cred = lib->creds->create(lib->creds, type, subtype,
									 BUILD_FROM_FD, 0, BUILD_END);
	}

	if (type == CRED_PRIVATE_KEY)
	{
		private = cred;
		if (!private)
		{
			fprintf(stderr, "parsing private key failed\n");
			return 1;
		}
		public = private->get_public_key(private);
		private->destroy(private);
	}
	else
	{
		cert = cred;
		if (!cert)
		{
			fprintf(stderr, "parsing certificate failed\n");
			return 1;
		}
		public = cert->get_public_key(cert);
		cert->destroy(cert);
	}
	if (!public)
	{
		fprintf(stderr, "extracting public key failed\n");
		return 1;
	}
	if (!public->get_encoding(public, form, &encoding))
	{
		fprintf(stderr, "public key encoding failed\n");
		public->destroy(public);
		return 1;
	}
	public->destroy(public);
	if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
	{
		fprintf(stderr, "writing public key failed\n");
		free(encoding.ptr);
		return 1;
	}
	free(encoding.ptr);
	return 0;
}

/**
 * Calculate the keyid of a key/certificate
 */
static int keyid(int argc, char *argv[])
{
	credential_type_t type = CRED_PRIVATE_KEY;
	int subtype = KEY_RSA;
	certificate_t *cert;
	private_key_t *private;
	public_key_t *public;
	char *file = NULL;
	void *cred;
	chunk_t id;

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case 'h':
				return usage(CMD_KEYID, NULL);
			case 't':
				if (streq(optarg, "rsa-priv"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa-priv"))
				{
					type = CRED_PRIVATE_KEY;
					subtype = KEY_ECDSA;
				}
				else if (streq(optarg, "pub"))
				{
					type = CRED_PUBLIC_KEY;
					subtype = KEY_ANY;
				}
				else if (streq(optarg, "x509"))
				{
					type = CRED_CERTIFICATE;
					subtype = CERT_X509;
				}
				else
				{
					return usage(CMD_KEYID, "invalid input type");
				}
				continue;
			case 'i':
				file = optarg;
				continue;
			case EOF:
				break;
			default:
				return usage(CMD_KEYID, "invalid --keyid option");
		}
		break;
	}
	if (file)
	{
		cred = lib->creds->create(lib->creds, type, subtype,
								  BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		cred = lib->creds->create(lib->creds, type, subtype,
								  BUILD_FROM_FD, 0, BUILD_END);
	}
	if (!cred)
	{
		fprintf(stderr, "parsing input failed\n");
		return 1;
	}

	if (type == CRED_PRIVATE_KEY)
	{
		private = cred;
		if (private->get_fingerprint(private, KEY_ID_PUBKEY_SHA1, &id))
		{
			printf("subjectKeyIdentifier:      %#B\n", &id);
		}
		if (private->get_fingerprint(private, KEY_ID_PUBKEY_INFO_SHA1, &id))
		{
			printf("subjectPublicKeyInfo hash: %#B\n", &id);
		}
		private->destroy(private);
	}
	else if (type == CRED_PUBLIC_KEY)
	{
		public = cred;
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &id))
		{
			printf("subjectKeyIdentifier:      %#B\n", &id);
		}
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_INFO_SHA1, &id))
		{
			printf("subjectPublicKeyInfo hash: %#B\n", &id);
		}
		public->destroy(public);
	}
	else
	{
		cert = cred;
		public = cert->get_public_key(cert);
		if (!public)
		{
			fprintf(stderr, "extracting public key from certificate failed");
			return 1;
		}
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &id))
		{
			printf("subjectKeyIdentifier:      %#B\n", &id);
		}
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_INFO_SHA1, &id))
		{
			printf("subjectPublicKeyInfo hash: %#B\n", &id);
		}
		public->destroy(public);
		cert->destroy(cert);
	}
	return 0;
}

/**
 * Create a self signed certificate.
 */
static int self(int argc, char *argv[])
{
	key_type_t type = KEY_RSA;
	hash_algorithm_t digest = HASH_SHA1;
	certificate_t *cert = NULL;
	private_key_t *private = NULL;
	public_key_t *public = NULL;
	char *file = NULL, *dn = NULL, *hex = NULL, *error = NULL;
	identification_t *id = NULL;
	linked_list_t *san;
	int lifetime = 1080;
	chunk_t serial = chunk_empty;
	chunk_t encoding = chunk_empty;
	time_t not_before, not_after;
	x509_flag_t flags = 0;
	options_t *options;

	options = options_create();
	san = linked_list_create();

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
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
				if (streq(optarg, "rsa"))
				{
					type = KEY_RSA;
				}
				else if (streq(optarg, "ecdsa"))
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
			case 'c':
				flags |= X509_CA;
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
						BUILD_SUBJECT_ALTNAMES, san, BUILD_END);
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
	return usage(CMD_SELF, error);
}

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
		switch (getopt_long(argc, argv, "", long_opts, NULL))
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
	return usage(CMD_ISSUE, error);
}

/**
 * Verify a certificate signature
 */
static int verify(int argc, char *argv[])
{
	certificate_t *cert, *ca;
	char *file = NULL, *cafile = NULL;
	bool good = FALSE;

	struct option long_opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "in", required_argument, NULL, 'i' },
		{ "cacert", required_argument, NULL, 'c' },
		{ 0,0,0,0 }
	};

	while (TRUE)
	{
		switch (getopt_long(argc, argv, "", long_opts, NULL))
		{
			case 'h':
				return usage(CMD_VERIFY, NULL);
			case 'i':
				file = optarg;
				continue;
			case 'c':
				cafile = optarg;
				continue;
			case EOF:
				break;
			default:
				return usage(CMD_VERIFY, "invalid --verify option");
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
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_FROM_FD, 0, BUILD_END);
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
	if (cert->issued_by(cert, ca))
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
 * Library initialization and operation parsing
 */
int main(int argc, char *argv[])
{
	int op, i;

	atexit(library_deinit);
	if (!library_init(STRONGSWAN_CONF))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (lib->integrity &&
		!lib->integrity->check_file(lib->integrity, "pki", argv[0]))
	{
		fprintf(stderr, "integrity check of pki failed\n");
		exit(SS_RC_DAEMON_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins, PLUGINDIR,
			lib->settings->get_str(lib->settings, "pki.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	build_opts(CMD_HELP);
	op = getopt_long(argc, argv, "", long_opts, NULL);
	for (i = 0; i < CMD_MAX; i++)
	{
		if (cmds[i].op == op)
		{
			build_opts(i);
			return cmds[i].call(argc, argv);
		}
	}
	return usage(CMD_HELP, "invalid operation");
}

