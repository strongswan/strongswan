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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>

#include "pki.h"

#include <asn1/asn1.h>
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
			printf("[%2d] \"%Y\" (CA, %s)\n", index++, cert->get_subject(cert),
				   x509->get_flags(x509) & X509_SELF_SIGNED ? "root"
															: "intermediate");
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
 * Build and allocate a path for a given certificate
 */
static bool build_pathname(int index, int total, char *template,
						   cred_encoding_type_t outform, char **path)
{
	char *dirname, *basename, *dot, *suffix;
	int len, written;

	dirname = path_dirname(template);
	basename = path_basename(template);

	suffix = (outform == CERT_ASN1_DER) ? "der" : "pem";

	dot = strrchr(basename, '.');
	len = dot ? (dot - basename) : strlen(basename);
	if (dot && (dot[1] != '\0'))
	{
		suffix = dot + 1;
	}

	if (total > 1)
	{
		written = asprintf(path, "%s%s%.*s-%d.%s", dirname, DIRECTORY_SEPARATOR,
						   len, basename, index, suffix);
	}
	else
	{
		written = asprintf(path, "%s%s%.*s.%s", dirname, DIRECTORY_SEPARATOR,
						   len, basename, suffix);
	}
	free(basename);
	free(dirname);
	return written > 0;
}

/**
 * Export selection modes if not using a specific index
 */
typedef enum {
	EXPORT_ALL,
	EXPORT_NO_ROOT,
	EXPORT_ROOT,
	EXPORT_CA,
	EXPORT_IM,
	EXPORT_EE,
} export_mode_t;

ENUM(export_mode_names, EXPORT_ALL, EXPORT_EE,
	"all",
	"no-root",
	"root",
	"ca",
	"im",
	"ee",
);

/**
 * Check if a certificate is selected for export
 */
static bool cert_selected(export_mode_t mode, x509_t *x509)
{
	bool is_self = x509->get_flags(x509) & X509_SELF_SIGNED;
	bool is_ca = x509->get_flags(x509) & X509_CA;

	switch (mode)
	{
		case EXPORT_NO_ROOT:
			return !(is_ca && is_self);
		case EXPORT_ROOT:
			return is_ca && is_self;
		case EXPORT_CA:
			return is_ca;
		case EXPORT_IM:
			return is_ca && !is_self;
		case EXPORT_EE:
			return !is_ca;
		default:
			return TRUE;
	}
}

/**
 * Export a certificate from a PEM certificate bundle
 */
static int export(pem_t *bundle, char *selector, char *template,
				  cred_encoding_type_t outform, bool reverse, bool force)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	array_t *selected = NULL;
	export_mode_t mode = EXPORT_ALL;
	chunk_t encoding;
	char *end, *path;
	uint32_t index = 0;
	int i = 1, count = 0, ret = 1;

	if (!enum_from_name(export_mode_names, selector, &mode) &&
		(!uint32_from_string(selector, &end, 10, &index) || *end != '\0' ||
		 !index))
	{
		fprintf(stderr, "invalid selector\n");
		return 1;
	}

	enumerator = bundle->create_cert_enumerator(bundle);
	while (enumerator->enumerate(enumerator, &cert))
	{
		if (!index)
		{
			if (!cert_selected(mode, (x509_t*)cert))
			{
				continue;
			}
		}
		else if (i++ != index)
		{
			continue;
		}
		array_insert_create(&selected, reverse ? ARRAY_HEAD : ARRAY_TAIL,
							cert->get_ref(cert));
	}
	enumerator->destroy(enumerator);

	count = array_count(selected);
	if (!count)
	{
		if (index)
		{
			fprintf(stderr, "invalid index %u\n", index);
		}
		else
		{
			fprintf(stderr, "no certificates match '%N' selector\n",
					export_mode_names, mode);
		}
		return 1;
	}

	if (!template && count > 1 && outform != CERT_PEM)
	{
		fprintf(stderr, "forcing PEM format to export multiple certificates to "
				"STDOUT\n");
		outform = CERT_PEM;
	}

	i = 1;
	while (array_remove(selected, ARRAY_HEAD, &cert))
	{
		if (!cert->get_encoding(cert, outform, &encoding))
		{
			fprintf(stderr, "unable to encode certificate\n");
			cert->destroy(cert);
			goto out;
		}
		cert->destroy(cert);

		if (template)
		{
			if (!build_pathname(i, count, template, outform, &path))
			{
				fprintf(stderr, "failed to create path to export certificate\n");
				free(encoding.ptr);
				goto out;
			}
			if (!chunk_write(encoding, path, 0022, force))
			{
				fprintf(stderr, "unable to write certificate to '%s': %s\n",
						path, strerror(errno));
				free(encoding.ptr);
				free(path);
				goto out;
			}
			free(path);
		}
		else
		{
			set_file_mode(stdout, outform);
			if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
			{
				fprintf(stderr, "certificate export failed\n");
				free(encoding.ptr);
				goto out;
			}
		}
		free(encoding.ptr);
		i++;
	}
	fprintf(stderr, "exported %d certificates\n", count);
	ret = 0;
out:
	array_destroy_offset(selected, offsetof(certificate_t, destroy));
	return ret;
}

/**
 * Create a bundle file from a list of certificates
 */
static int create(array_t *certs)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	chunk_t encoding;

	if (!array_count(certs))
	{
		return command_usage("missing certificates to create bundle");
	}

	enumerator = array_create_enumerator(certs);
	while (enumerator->enumerate(enumerator, &cert))
	{
		if (cert->get_encoding(cert, CERT_PEM, &encoding))
		{
			if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
			{
				fprintf(stderr, "failed to write certificate to stdout\n");
				free(encoding.ptr);
				enumerator->destroy(enumerator);
				return 1;
			}
			free(encoding.ptr);
		}
		else
		{
			fprintf(stderr, "unable to encode certificate in PEM format\n");
			enumerator->destroy(enumerator);
			return 1;
		}
	}
	enumerator->destroy(enumerator);
	return 0;
}

/**
 * Add the parsed certificate/bundle to the list
 */
static bool add_certs(array_t **certs, char *path)
{
	certificate_t *cert;
	enumerator_t *enumerator;
	pem_t *pem = NULL;
	chunk_t *mapped = NULL, chunk = chunk_empty;
	bool success = FALSE;

	if (streq(path, "-"))
	{
		set_file_mode(stdin, CERT_ASN1_DER);
		if (!chunk_from_fd(0, &chunk))
		{
			fprintf(stderr, "reading input failed: %s\n", strerror(errno));
			return FALSE;
		}
	}
	else
	{
		mapped = chunk_map(path, FALSE);
		if (!mapped)
		{
			fprintf(stderr, "reading '%s' failed: %s\n", path, strerror(errno));
			return FALSE;
		}
		chunk = *mapped;
	}

	if (!is_asn1(chunk))
	{
		pem = lib->creds->create(lib->creds, CRED_CONTAINER, CONTAINER_PEM,
								 BUILD_BLOB, chunk, BUILD_END);
	}
	if (pem)
	{
		enumerator = pem->create_cert_enumerator(pem);
		while (enumerator->enumerate(enumerator, &cert))
		{
			array_insert_create(certs, ARRAY_TAIL, cert->get_ref(cert));
		}
		enumerator->destroy(enumerator);
		pem->container.destroy(&pem->container);
	}
	else
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB, chunk, BUILD_END);
		if (!cert)
		{
			goto out;
		}
		array_insert_create(certs, ARRAY_TAIL, cert);
	}
	success = TRUE;

out:
	if (mapped)
	{
		chunk_unmap(mapped);
	}
	else
	{
		free(chunk.ptr);
	}
	return success;
}

/**
 * Handle PEM certificate bundles
 */
static int bundle()
{
	cred_encoding_type_t outform = CERT_ASN1_DER;
	char *arg, *file = NULL, *selector = NULL, *template = NULL;
	pem_t *pem = NULL;
	array_t *certs = NULL;
	int res = 1;
	bool reverse = FALSE, force = FALSE;
	enum {
		OP_NONE,
		OP_LIST,
		OP_EXPORT,
		OP_CREATE,
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
			case 'o':
				template = arg;
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
				selector = arg;
				continue;
			case 'r':
				reverse = TRUE;
				continue;
			case 'F':
				force = TRUE;
				continue;
			case 'f':
				if (!get_form(arg, &outform, CRED_CERTIFICATE))
				{
					return command_usage("invalid output format");
				}
				continue;
			case 'C':
				if (op != OP_NONE)
				{
					goto invalid;
				}
				op = OP_CREATE;
				continue;
			case 'c':
				if (!add_certs(&certs, arg))
				{
					array_destroy_offset(certs, offsetof(certificate_t, destroy));
					return command_usage("parsing certificate failed");
				}
				continue;
			case EOF:
				break;
			default:
			invalid:
				return command_usage("invalid --bundle option");
		}
		break;
	}

	if (op != OP_CREATE)
	{
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
	}

	switch (op)
	{
		case OP_LIST:
			res = show(pem);
			break;
		case OP_EXPORT:
			res = export(pem, selector, template, outform, reverse, force);
			break;
		case OP_CREATE:
			res = create(certs);
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
	array_destroy_offset(certs, offsetof(certificate_t, destroy));
	return res;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		bundle, 'b', "bundle", "PEM certificate bundle functions",
		{"--export selector|--list [--in file]|--create [--cert -|file]+",
		 "[--out file|template] [--reverse] [--force] [--outform der|pem]"},
		{
			{"help",	'h', 0, "show usage information"},
			{"in",		'i', 1, "input file, default: stdin"},
			{"list",	'l', 0, "list certificates"},
			{"export",	'e', 1, "export certificates in a bundle"},
			{"out",		'o', 1, "export output file/template, default: stdout"},
			{"reverse",	'r', 0, "reverse the certificate order when exporting"},
			{"force",	'F', 0, "force overwriting existing files"},
			{"outform",	'f', 1, "encoding of exported certificate, default: der"},
			{"create",	'C', 0, "create a bundle from multiple certificates"},
			{"cert",	'c', 1, "certificate/bundle to place into a new bundle"},
		}
	});
}
